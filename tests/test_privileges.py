"""PUID/PGID: drop fully and verifiably, or refuse to start."""
import os

import pytest

from conftest import app_module


class FakeOS:
    """Just the os surface _drop_privileges uses, with a real filesystem
    walk but simulated identity calls."""
    path = os.path
    walk = staticmethod(os.walk)

    def __init__(self, euid=0, fail=None, sticky_groups=(), can_regain_root=False, ignore_setuid=False):
        self.uid = self.euid = euid
        self.gid = self.egid = euid
        self.groups = [0, 4, 27] if euid == 0 else []
        self.fail = fail or set()
        self.sticky_groups = list(sticky_groups)
        self.can_regain_root = can_regain_root
        self.ignore_setuid = ignore_setuid
        self.chowned = []

    def geteuid(self): return self.euid
    def getuid(self): return self.uid
    def getgid(self): return self.gid
    def getegid(self): return self.egid
    def getgroups(self): return list(self.groups)

    def chown(self, p, uid, gid, follow_symlinks=True):
        if "chown" in self.fail: raise PermissionError("chown denied")
        self.chowned.append((p, follow_symlinks))

    def setgroups(self, groups):
        if "setgroups" in self.fail: raise PermissionError("setgroups denied")
        self.groups = list(groups) + self.sticky_groups

    def setgid(self, gid):
        if "setgid" in self.fail: raise PermissionError("setgid denied")
        self.gid = self.egid = gid

    def setuid(self, uid):
        if uid == 0 and self.euid != 0 and not self.can_regain_root:
            raise PermissionError("not permitted")
        if "setuid" in self.fail: raise PermissionError("setuid denied")
        if self.ignore_setuid: return
        self.uid = self.euid = uid


def test_successful_drop_is_verified_and_clears_groups(tmp_path):
    (tmp_path / "data" / "sub").mkdir(parents=True)
    (tmp_path / "data" / "sub" / "x.db").write_text("x")
    fos = FakeOS()
    assert app_module._drop_privileges("99", "100", tmp_path / "data", _os=fos) == (99, 100)
    assert (fos.uid, fos.euid, fos.gid, fos.egid) == (99, 99, 100, 100)
    assert fos.groups == []
    # Data dir contents re-owned without following symlinks; photos never touched.
    assert all(follow is False for _, follow in fos.chowned[1:])
    assert len(fos.chowned) == 3


@pytest.mark.parametrize("fail", ["setuid", "setgid", "setgroups", "chown"])
def test_failed_drop_aborts(tmp_path, fail):
    with pytest.raises(SystemExit):
        app_module._drop_privileges("99", "100", tmp_path, _os=FakeOS(fail={fail}))


def test_drop_that_silently_does_nothing_aborts(tmp_path):
    with pytest.raises(SystemExit):
        app_module._drop_privileges("99", "100", tmp_path, _os=FakeOS(ignore_setuid=True))


def test_leftover_supplementary_groups_abort(tmp_path):
    with pytest.raises(SystemExit):
        app_module._drop_privileges("99", "100", tmp_path, _os=FakeOS(sticky_groups=[27]))


def test_able_to_regain_root_aborts(tmp_path):
    with pytest.raises(SystemExit):
        app_module._drop_privileges("99", "100", tmp_path, _os=FakeOS(can_regain_root=True))


@pytest.mark.parametrize("puid,pgid", [("99", ""), ("", "100"), ("abc", "100"), ("-1", "100"), ("0", "100")])
def test_ambiguous_configuration_aborts(tmp_path, puid, pgid):
    with pytest.raises(SystemExit):
        app_module._drop_privileges(puid, pgid, tmp_path, _os=FakeOS())


def test_non_root_mismatch_aborts_and_match_is_fine(tmp_path):
    fos = FakeOS(euid=1000)
    with pytest.raises(SystemExit):
        app_module._drop_privileges("99", "100", tmp_path, _os=fos)
    fos = FakeOS(euid=99); fos.gid = fos.egid = 100
    assert app_module._drop_privileges("99", "100", tmp_path, _os=fos) == (99, 100)


def test_unset_keeps_running_with_warning_and_explicit_root(tmp_path, capsys):
    assert app_module._drop_privileges("", "", tmp_path, _os=FakeOS()) is None
    assert app_module._drop_privileges("0", "0", tmp_path, _os=FakeOS()) == (0, 0)
