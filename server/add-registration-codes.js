const db = require('./database');
const crypto = require('crypto');

function genCode(len = 10) {
  return crypto.randomBytes(len).toString('base64').replace(/[^A-Z0-9]/ig, '').slice(0, 10).toUpperCase();
}

function addCodesForUsers() {
  const users = db.prepare('SELECT id, username, role FROM users').all();
  console.log(`Found ${users.length} users`);

  const getCodeByUser = db.prepare('SELECT * FROM registration_codes WHERE used_by = ?');
  const insert = db.prepare("INSERT INTO registration_codes (code, role, used, used_by, created_at) VALUES (?, ?, 1, ?, datetime('now'))");
  const getByCode = db.prepare('SELECT id FROM registration_codes WHERE code = ?');

  let inserted = 0;
  for (const u of users) {
    const existing = getCodeByUser.get(u.id);
    if (existing) continue;

    // ensure unique code
    let code;
    let tries = 0;
    do {
      code = genCode(8);
      tries++;
      if (tries > 10) throw new Error('Unable to generate unique code');
    } while (getByCode.get(code));

    insert.run(code, u.role || 'general', u.id);
    inserted++;
    console.log(` -> Inserted code for user ${u.username} (${u.id}): ${code}`);
  }

  console.log(`Inserted ${inserted} registration codes`);
}

try {
  addCodesForUsers();
  process.exit(0);
} catch (err) {
  console.error('Error adding registration codes:', err);
  process.exit(1);
}
