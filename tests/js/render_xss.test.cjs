/*
 * Renders templates/index.html in jsdom with a stubbed API that returns
 * hostile filenames, metadata and error strings, drives every view that
 * displays them, clicks the dynamic controls, and checks that all of it
 * stayed inert text.
 *
 *   npm install jsdom@24        (anywhere on NODE_PATH)
 *   node tests/js/render_xss.test.cjs [path/to/index.html]
 *
 * Exits non-zero on any failure. Pointing it at the pre-hardening template
 * (git show 548f1d4:templates/index.html) is expected to fail.
 */
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const templatePath = process.argv[2] || path.join(__dirname, '..', '..', 'templates', 'index.html');
const html = fs.readFileSync(templatePath, 'utf8')
  .replace(/\{\{\s*version\s*\}\}/g, 'test')
  .replace(/\{\{\s*csrf_token\s*\}\}/g, 'tok123');

// Markup injection, attribute breakout, and the inline-handler case where
// an HTML character reference is decoded back to a quote before the JS runs.
const TAG = `<img src=x onerror="window.__pwned=(window.__pwned||[]).concat('tag')"><b id="injected">b</b>`;
const ATTR = `" onmouseover="window.__pwned=['attr']" x="`;
const ENTITY_ID = `x&#39;);window.__pwned=[/entity/.source];//.jpg`;  // no raw quote for the old escaping to catch
const QUOTE_ID = `x');window.__pwned=(window.__pwned||[]).concat('quote');//.jpg`;
const HOSTILE = [TAG, ATTR, ENTITY_ID, QUOTE_ID];

const photo = (id, extra = {}) => ({
  id, path: '/photos/' + id, filename: TAG + ATTR, folder: TAG, location_name: TAG,
  status: 'named', date_taken: '2024-06-12T10:00:00', has_gps: 0, camera: TAG, lens: ATTR,
  size_kb: 10, ...extra,
});

const api = {
  '/api/config': { ai_model: 'm', geocoder_providers: [], dry_run: true, has_ai_key: false,
                   default_photo_root: '/photos', allowed_roots: ['/photos'] },
  '/api/sessions': { sessions: [{ id: 1, name: TAG, scan_root: ATTR, created_at: '', last_used: '' }] },
  '/api/pending': { count: 1, photo_count: 1, pending: [{ photo_id: ENTITY_ID, filename: TAG, folder: ATTR,
                    path: '/x', changes: [{ id: 1, field: TAG, old_value: TAG, new_value: ATTR }] }] },
  '/api/duplicates/result': { total_groups: 1, scanned: 2, phash_groups: [], fname_groups: [],
                              exact_groups: [[photo(ENTITY_ID), photo(QUOTE_ID)]] },
  '/api/logs': { last_id: 1, lines: [{ id: 1, ts: '2024-01-01T00:00:00', line: TAG }] },
  '/api/history/imports': { total_points: 0, imports: [
    { id: 1, source_name: TAG, source_type: 'gpx', status: 'error', error: TAG, point_count: 0 }] },
  '/api/scan_progress': { phase: 'error', error: TAG, message: TAG, current: 0, total: 0 },
  '/api/geocode_search': { results: [{ name: TAG, lat: 1, lon: 2 }] },
  '/api/browse': { path: '/photos', parent: null, dirs: [TAG, ATTR], roots: ['/photos', TAG] },
  '/api/rename_preview': { preview: [{ id: ENTITY_ID, old_filename: TAG, new_filename: ATTR, unchanged: false }] },
  '/api/saved_locations': { saved: [{ name: TAG, lat: 1, lon: 2 }], frequent: [{ name: ATTR, count: 3 }] },
  '/api/duplicates/start': { cached: true },
};

const calls = [];
function stubFetch(url, opts = {}) {
  calls.push({ url: String(url), opts });
  const key = Object.keys(api).find(k => String(url).startsWith(k));
  const body = key ? api[key] : {};
  const res = { ok: true, status: 200, json: async () => JSON.parse(JSON.stringify(body)) };
  res.clone = () => res;
  return Promise.resolve(res);
}

const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); };

(async () => {
  const dom = new JSDOM(html, {
    url: 'http://localhost/', runScripts: 'dangerously', pretendToBeVisual: true,
    beforeParse(window) {
      window.fetch = stubFetch;
      window.L = { map: () => ({ setView() { return this; }, on() {}, invalidateSize() {}, removeLayer() {} }),
                   tileLayer: () => ({ addTo() {} }), marker: () => ({ addTo() { return this; } }) };
      window.CSS = window.CSS || { escape: s => String(s).replace(/["\\]/g, '\\$&') };
    },
  });
  const w = dom.window;
  const tick = () => new Promise(r => setTimeout(r, 30));
  await tick();
  const run = async (label, code) => {
    try { await w.eval(`(async()=>{ ${code} })()`); await tick(); }
    catch (e) { failures.push(`${label}: threw ${e && e.message}`); }
  };

  await run('grid', `allPhotos=[${JSON.stringify(photo(ENTITY_ID))},${JSON.stringify(photo(QUOTE_ID))}];
                     recomputeFiltered(); renderGrid();`);
  for (const hit of w.document.querySelectorAll('#photoGrid .select-hit')) hit.click();
  await run('grid-selection', `window.__selected=[...selected];`);
  check(JSON.stringify([...w.__selected].sort()) === JSON.stringify([ENTITY_ID, QUOTE_ID].sort()),
        'grid: select toggles must use the exact photo id');
  for (const hit of w.document.querySelectorAll('#photoGrid .select-hit'))
    hit.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));

  await run('detail', `openDetail(0);`);
  await run('pending', `currentScanRoot='/photos'; await openPendingModal();`);
  await run('dups', `currentScanRoot='/photos'; await renderDupResult();`);
  for (const cb of w.document.querySelectorAll('#dupList input[type=checkbox]')) {
    cb.checked = true; cb.dispatchEvent(new w.Event('change', { bubbles: true }));
  }
  await run('dup-marks', `window.__marks=[..._dupMarks];`);
  check(JSON.stringify([...w.__marks].sort()) === JSON.stringify([ENTITY_ID, QUOTE_ID].sort()),
        'duplicates: checkbox must mark the exact photo id');
  for (const b of w.document.querySelectorAll('#dupList button')) b.click();

  await run('logs', `_logsSinceId=0; _logsPaused=false; await pollLogs();`);
  await run('history', `await loadHistoryImports();`);
  await run('scan-error', `_activeView='empty'; await pollProgress();`);
  await run('progress', `showProgress(${JSON.stringify(TAG)}, 1, 2);`);
  await run('sessions', `await loadSessions();`);
  await run('browser', `await loadBrowser('/photos');`);
  await run('rename', `selected=new Set([${JSON.stringify(ENTITY_ID)}]); await previewRename();`);
  await run('saved', `await toggleSavedLocations();`);
  await run('map', `openMapPicker('detail'); document.getElementById('mapSearchInput').value='q';
                    await mapSearch(); selectMapSearchResult(0);`);
  await run('seed', `_seedMode='location'; _seedTargets=[${JSON.stringify(photo(ENTITY_ID, { status: TAG }))}];
                     _seedUnchecked=new Set(); _seedFilter='all'; renderSeedTabs(); renderSeedGrid();`);
  await run('toast', `toast(${JSON.stringify(TAG)}, 'error');`);
  await run('confirm', `customConfirm(${JSON.stringify(TAG)}); document.querySelector('[data-role="cancel"]').click();`);

  // Fire every mouse/click handler on every dynamic element we rendered.
  for (const el of w.document.querySelectorAll('#photoGrid *, #pendingModalList *, #dupList *, #logsView *, '
      + '#historyImportList *, #emptyState *, #sessionList *, #browserList *, #renamePreviewList *, '
      + '#savedLocationsDropdown *, #mapSearchResults *, #mapCoords *, #seedChecklist *, #seedFilterTabs *, #detailExifInfo *')) {
    for (const type of ['mouseover', 'mouseenter', 'focus']) el.dispatchEvent(new w.Event(type));
  }
  await tick();

  check(w.__pwned === undefined, `script ran: ${JSON.stringify(w.__pwned)}`);
  check(w.document.querySelectorAll('img[src="x"]').length === 0, 'injected <img> element exists');
  check(!w.document.getElementById('injected'), 'injected <b id=injected> element exists');
  const handlerAttrs = [...w.document.querySelectorAll('*')].flatMap(el =>
    [...el.attributes].filter(a => a.name.startsWith('on') && /__pwned/.test(a.value)).map(a => a.name));
  check(handlerAttrs.length === 0, `hostile inline handler attributes: ${handlerAttrs.join(',')}`);
  const text = w.document.body.textContent;
  check(text.includes(TAG), 'hostile text should be displayed literally (as text)');

  // Every change-making request carried the page token; reads didn't need it.
  const mutations = calls.filter(c => (c.opts.method || 'GET').toUpperCase() !== 'GET');
  const tokenOk = mutations.every(c => new w.Headers(c.opts.headers || {}).get('X-PhotoTagger-CSRF') === 'tok123');
  check(tokenOk, 'a POST/DELETE went out without the page token');

  if (failures.length) {
    console.error('FAIL\n - ' + failures.join('\n - '));
    process.exit(1);
  }
  console.log(`PASS: ${HOSTILE.length} hostile payloads across grid, detail, pending, duplicates, logs, ` +
              `history, scan errors, progress, sessions, browser, rename, saved locations, map, seed checklist; ` +
              `${mutations.length} mutating request(s) carried the token`);
  process.exit(0);
})();
