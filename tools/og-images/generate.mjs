// 為每篇文章產生專屬 OG 分享圖（1200×630）。
// 在 GitHub Actions 的 Jekyll 建置「之後」執行：讀 _site 裡每篇文章的 index.html，
// 取出標題與分類，畫成一張深色招牌風的圖，存成同資料夾的 og.png。
// default.html 的 og:image 指向「文章網址 + og.png」，所以路徑一定對得上。
import { chromium } from 'playwright';
import { readFileSync, readdirSync, statSync } from 'fs';
import { join, dirname } from 'path';

const siteDir = process.argv[2];
if (!siteDir) {
  console.error('用法：node generate.mjs <_site 目錄>');
  process.exit(1);
}

// 遞迴找出所有 index.html
function walk(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, acc);
    else if (name === 'index.html') acc.push(p);
  }
  return acc;
}

// 還原常見 HTML 實體
function decode(s) {
  return s
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(+n));
}

// 從 HTML 抓 <meta property/name="prop" content="...">（兩種屬性順序都試）
function meta(html, prop) {
  const a = html.match(new RegExp('<meta[^>]+(?:property|name)="' + prop + '"[^>]+content="([^"]*)"', 'i'));
  if (a) return decode(a[1]);
  const b = html.match(new RegExp('<meta[^>]+content="([^"]*)"[^>]+(?:property|name)="' + prop + '"', 'i'));
  return b ? decode(b[1]) : null;
}

// 防注入：把使用者標題丟進 HTML 前先跳脫
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const template = (title, category) => `<!doctype html><html lang="zh-TW"><head><meta charset="utf-8">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/lxgw-wenkai-tc-webfont@1.2.0/style.css">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+TC:wght@500;700&display=swap">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { width:1200px; height:630px; background:#1a1a1a; overflow:hidden;
    font-family:"LXGW WenKai TC","Noto Sans TC",sans-serif; position:relative; }
  .bar { position:absolute; left:0; top:0; bottom:0; width:14px; background:#7c93b0; }
  .wrap { position:absolute; inset:0; padding:82px 92px 76px 108px; display:flex; flex-direction:column; }
  .site { font-family:"Noto Sans TC",sans-serif; font-size:27px; color:#8a8a8a; letter-spacing:.06em; }
  .cat { display:inline-block; align-self:flex-start; margin-top:16px; padding:6px 16px;
    border:1px solid #7c93b0; border-radius:999px; font-family:"Noto Sans TC",sans-serif;
    font-size:23px; color:#7c93b0; font-weight:700; }
  .title { margin-top:auto; font-size:66px; line-height:1.42; color:#ededed; font-weight:700;
    display:-webkit-box; -webkit-line-clamp:4; -webkit-box-orient:vertical; overflow:hidden; }
  .title.small { font-size:52px; line-height:1.45; -webkit-line-clamp:5; }
  .foot { margin-top:36px; font-family:"Noto Sans TC",sans-serif; font-size:24px;
    color:#6f6f6f; letter-spacing:.04em; }
</style></head><body>
  <div class="bar"></div>
  <div class="wrap">
    <div class="site">無聊男子的自言自語</div>
    ${category ? `<div class="cat">${category}</div>` : ''}
    <div class="title ${title.length > 34 ? 'small' : ''}">${title}</div>
    <div class="foot">tediousman.github.io</div>
  </div>
</body></html>`;

// 只處理網址形如 /分類/YYYY/MM/DD/標題/ 的文章頁
const posts = walk(siteDir).filter((f) => /[\/\\]\d{4}[\/\\]\d{2}[\/\\]\d{2}[\/\\]/.test(f));
console.log(`找到 ${posts.length} 篇文章頁`);

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1 });

// 從檔案路徑取分類：/分類/YYYY/MM/DD/ 的第一段（磁碟上是真實 unicode 資料夾名）
function categoryFromPath(f) {
  const m = f.replace(/\\/g, '/').match(/([^/]+)\/\d{4}\/\d{2}\/\d{2}\//);
  return m ? m[1] : null;
}

let n = 0;
for (const f of posts) {
  const html = readFileSync(f, 'utf8');
  const title = meta(html, 'og:title') || '無聊男子的自言自語';
  const category = meta(html, 'article:section') || categoryFromPath(f);
  await page.setContent(template(esc(title), category ? esc(category) : null), { waitUntil: 'networkidle' });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(400); // 霞鶩文楷分段載入，多等一下確保字體上場
  const out = join(dirname(f), 'og.png');
  await page.screenshot({ path: out });
  n++;
  console.log(`  ✓ ${out.replace(siteDir, '')} — ${title}`);
}

await browser.close();
console.log(`完成，共產出 ${n} 張 OG 圖`);
