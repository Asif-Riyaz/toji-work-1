const fs = require('node:fs');
const path = require('node:path');

console.log('📦 Starting Toji build for Netlify...');

// 1. Create public directory if not exists
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true });
}

// 2. Copy index.html to public/
const srcHtml = path.join(__dirname, 'index.html');
const destHtml = path.join(publicDir, 'index.html');
if (fs.existsSync(srcHtml)) {
  fs.copyFileSync(srcHtml, destHtml);
  console.log('✅ Copied index.html to public/index.html');
}

// 3. Copy image assets if present
['figma_thumb.png', 'figma_thumbnail.png', 'toji1.jpg', 'toji2.jpg'].forEach(img => {
  const src = path.join(__dirname, img);
  const dest = path.join(publicDir, img);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dest);
    console.log(`✅ Copied ${img} to public/`);
  }
});

// 4. Ensure SQLite WAL is checkpointed if db.js is available locally
try {
  if (fs.existsSync(path.join(__dirname, 'toji.db'))) {
    const db = require('./db.js');
    if (db && db.raw && typeof db.raw.exec === 'function') {
      db.raw.exec('PRAGMA wal_checkpoint(TRUNCATE);');
      console.log('✅ SQLite WAL checkpointed to toji.db');
    }
  }
} catch (err) {
  console.log('ℹ️ SQLite checkpoint skipped (using JSON store)');
}

console.log('🎉 Toji build completed successfully! Ready for Netlify deployment.');
