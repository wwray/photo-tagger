/*
 * The enlarged hover preview in the Propagate/Push-date picker sits at the
 * top of <body>, so a wheel over it used to scroll the page behind the
 * modal. It must scroll the picker's own list instead.
 *
 *   node tests/js/preview_scroll.test.cjs   (needs jsdom on NODE_PATH)
 */
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const html = fs.readFileSync(path.join(__dirname, '..', '..', 'templates', 'index.html'), 'utf8')
  .replace(/\{\{\s*version\s*\}\}/g, 'test').replace(/\{\{\s*csrf_token\s*\}\}/g, 'tok');

(async () => {
  const dom = new JSDOM(html, {
    url: 'http://localhost/', runScripts: 'dangerously', pretendToBeVisual: true,
    beforeParse(w) {
      const body = { sessions: [], geocoder_providers: [], dry_run: true };
      w.fetch = () => Promise.resolve({ ok: true, status: 200, json: async () => body, clone() { return this; } });
    },
  });
  const w = dom.window, d = w.document;
  await new Promise(r => setTimeout(r, 30));
  const failures = [];

  w.eval(`_seedMode='location'; _seedFilter='all'; _seedUnchecked=new Set();
          _seedTargets=[1,2,3].map(i=>({id:'p'+i+'.jpg', filename:'p'+i+'.jpg', status:'unknown', path:'/x'}));
          document.getElementById('seedModal').style.display='flex'; renderSeedGrid();`);
  const list = d.getElementById('seedChecklist');
  const scrolled = [];
  list.scrollBy = (x, y) => scrolled.push(y);           // jsdom has no layout/scrolling
  let pageScrolled = false;
  w.scrollBy = w.scrollTo = () => { pageScrolled = true; };

  const card = list.querySelector('.seed-item');
  card.dispatchEvent(new w.MouseEvent('mouseenter'));
  const preview = d.getElementById('photoHoverPreview');
  if (preview.style.display !== 'block') failures.push('preview did not open on hover');

  const wheel = new w.WheelEvent('wheel', { deltaY: 120, deltaMode: 0, bubbles: true, cancelable: true });
  preview.dispatchEvent(wheel);
  if (!wheel.defaultPrevented) failures.push('wheel over the preview was not kept from scrolling the page');
  if (JSON.stringify(scrolled) !== '[120]') failures.push(`picker list should scroll by 120px, got ${JSON.stringify(scrolled)}`);
  if (pageScrolled) failures.push('page was scrolled');
  if (preview.style.display !== 'none') failures.push('preview should close after scrolling');

  // Line-mode wheels (some mice/OSes) are converted to pixels.
  card.dispatchEvent(new w.MouseEvent('mouseenter'));
  scrolled.length = 0;
  preview.dispatchEvent(new w.WheelEvent('wheel', { deltaY: 3, deltaMode: 1, bubbles: true, cancelable: true }));
  if (JSON.stringify(scrolled) !== '[48]') failures.push(`line-mode wheel should scroll 48px, got ${JSON.stringify(scrolled)}`);

  if (failures.length) { console.error('FAIL\n - ' + failures.join('\n - ')); process.exit(1); }
  console.log('PASS: wheel over the enlarged preview scrolls the picker list, not the page');
  process.exit(0);
})();
