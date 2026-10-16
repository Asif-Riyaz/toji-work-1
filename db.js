const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

// Detect serverless or cloud environment (Netlify, Render, AWS Lambda, Vercel)
const isServerless = Boolean(
  process.env.NETLIFY ||
  process.env.AWS_LAMBDA_FUNCTION_NAME ||
  process.env.LAMBDA_TASK_ROOT ||
  process.env.VERCEL ||
  process.env.RENDER
);

let DB_PATH;
if (isServerless) {
  const tmpDir = process.platform === 'win32' ? os.tmpdir() : '/tmp';
  const tmpDbPath = path.join(tmpDir, 'toji.db');

  if (!fs.existsSync(tmpDbPath)) {
    // Look for bundled seed database across common serverless locations
    const candidatePaths = [
      path.join(process.cwd(), 'toji.db'),
      path.join(__dirname, 'toji.db'),
      path.join(__dirname, '..', 'toji.db'),
      path.join(__dirname, '..', '..', 'toji.db')
    ];
    for (const src of candidatePaths) {
      if (fs.existsSync(src)) {
        try {
          fs.copyFileSync(src, tmpDbPath);
          break;
        } catch (e) {
          // ignore error and let DatabaseSync initialize
        }
      }
    }
  }
  DB_PATH = tmpDbPath;
} else {
  DB_PATH = path.join(__dirname, 'toji.db');
}

const db = new DatabaseSync(DB_PATH);

// Enable WAL mode, foreign keys, and normal synchronous for high performance
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA synchronous = NORMAL;
`);

// Create database schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_login_at TEXT
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

  CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    notes TEXT DEFAULT '',
    category TEXT NOT NULL DEFAULT 'Engineering',
    priority TEXT NOT NULL DEFAULT 'Medium',
    status TEXT NOT NULL DEFAULT 'active',
    planned_mins INTEGER NOT NULL DEFAULT 45,
    actual_mins INTEGER NOT NULL DEFAULT 0,
    date TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    completed_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_tasks_date ON tasks(date);
  CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);

  CREATE TABLE IF NOT EXISTS time_logs (
    id TEXT PRIMARY KEY,
    task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
    duration_seconds INTEGER NOT NULL,
    type TEXT NOT NULL DEFAULT 'focus',
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL,
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_timelogs_task ON time_logs(task_id);
  CREATE INDEX IF NOT EXISTS idx_timelogs_started ON time_logs(started_at);

  CREATE TABLE IF NOT EXISTS daily_summaries (
    date TEXT PRIMARY KEY,
    summary_text TEXT DEFAULT '',
    mood TEXT DEFAULT 'productive',
    blockers TEXT DEFAULT '',
    goals_tomorrow TEXT DEFAULT '',
    key_takeaways TEXT DEFAULT '',
    energy_rating INTEGER DEFAULT 3,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS classes (
    id TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    title TEXT NOT NULL,
    module TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    notes TEXT DEFAULT '',
    date TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS workouts (
    id TEXT PRIMARY KEY,
    exercise TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'Push',
    sets INTEGER DEFAULT 3,
    reps TEXT DEFAULT '12',
    weight TEXT DEFAULT 'Bodyweight',
    status TEXT NOT NULL DEFAULT 'pending',
    date TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS btech_subjects (
    id TEXT PRIMARY KEY,
    subject_name TEXT NOT NULL,
    code TEXT NOT NULL,
    credits INTEGER DEFAULT 3,
    internal_marks INTEGER DEFAULT 0,
    external_marks INTEGER DEFAULT 0,
    grade TEXT DEFAULT 'A',
    status TEXT NOT NULL DEFAULT 'ongoing'
  );

  CREATE TABLE IF NOT EXISTS coding_practice (
    id TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    problem_title TEXT NOT NULL,
    difficulty TEXT NOT NULL DEFAULT 'Medium',
    status TEXT NOT NULL DEFAULT 'solved',
    date TEXT NOT NULL,
    notes TEXT DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS subject_works (
    id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES btech_subjects(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'Assignment',
    status TEXT NOT NULL DEFAULT 'pending',
    deadline TEXT,
    created_at TEXT NOT NULL
  );
`);

// Safe column migrations for existing databases
try { db.exec(`ALTER TABLE daily_summaries ADD COLUMN key_takeaways TEXT DEFAULT ''`); } catch(e){}
try { db.exec(`ALTER TABLE daily_summaries ADD COLUMN energy_rating INTEGER DEFAULT 3`); } catch(e){}
try { db.exec(`ALTER TABLE btech_subjects ADD COLUMN semester INTEGER DEFAULT 5`); } catch(e){}
try { db.exec(`ALTER TABLE tasks ADD COLUMN subject_id TEXT`); } catch(e){}

// Seed default settings if not exists
const defaultSettings = {
  daily_goal_hours: '8.0',
  pomodoro_length: '25',
  short_break: '5',
  long_break: '15',
  sound_enabled: 'true',
  theme: 'dark'
};

const insertSettingStmt = db.prepare(`
  INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)
`);
for (const [k, v] of Object.entries(defaultSettings)) {
  insertSettingStmt.run(k, v);
}

// -----------------------------------------------------------------------------
// Database Query APIs
// -----------------------------------------------------------------------------

const dbApi = {
  // Direct raw handle if needed
  raw: db,

  // User management
  getUserCount() {
    const row = db.prepare(`SELECT COUNT(*) AS count FROM users`).get();
    return Number(row.count);
  },

  getOwner() {
    return db.prepare(`SELECT id, username, password_hash, password_salt, created_at, last_login_at FROM users LIMIT 1`).get();
  },

  createOwner(username, passwordHash, passwordSalt) {
    const now = new Date().toISOString();
    const result = db.prepare(`
      INSERT INTO users (username, password_hash, password_salt, created_at, last_login_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(username, passwordHash, passwordSalt, now, now);
    return { id: Number(result.lastInsertRowid), username, created_at: now };
  },

  updateOwnerPassword(userId, passwordHash, passwordSalt) {
    db.prepare(`
      UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?
    `).run(passwordHash, passwordSalt, userId);
  },

  updateLastLogin(userId) {
    db.prepare(`UPDATE users SET last_login_at = ? WHERE id = ?`).run(new Date().toISOString(), userId);
  },

  // Sessions
  createSession(token, userId, expiresAt, ipAddress = '', userAgent = '') {
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO sessions (token, user_id, created_at, expires_at, last_activity_at, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(token, userId, now, expiresAt, now, ipAddress, userAgent);
  },

  getSession(token) {
    const now = new Date().toISOString();
    return db.prepare(`
      SELECT s.token, s.user_id, s.expires_at, u.username
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.token = ? AND s.expires_at > ?
    `).get(token, now);
  },

  touchSession(token) {
    db.prepare(`UPDATE sessions SET last_activity_at = ? WHERE token = ?`).run(new Date().toISOString(), token);
  },

  deleteSession(token) {
    db.prepare(`DELETE FROM sessions WHERE token = ?`).run(token);
  },

  deleteUserSessions(userId) {
    db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(userId);
  },

  cleanupExpiredSessions() {
    const now = new Date().toISOString();
    db.prepare(`DELETE FROM sessions WHERE expires_at <= ?`).run(now);
  },

  // Tasks
  getTasks({ date, status, category, search } = {}) {
    let sql = `SELECT * FROM tasks WHERE 1=1`;
    const params = [];

    if (date) {
      sql += ` AND date = ?`;
      params.push(date);
    }
    if (status && status !== 'all') {
      sql += ` AND status = ?`;
      params.push(status);
    }
    if (category && category !== 'all') {
      sql += ` AND category = ?`;
      params.push(category);
    }
    if (search) {
      sql += ` AND (title LIKE ? OR notes LIKE ?)`;
      params.push(`%${search}%`, `%${search}%`);
    }

    sql += ` ORDER BY sort_order ASC, created_at DESC`;
    return db.prepare(sql).all(...params);
  },

  getTaskById(id) {
    return db.prepare(`SELECT * FROM tasks WHERE id = ?`).get(id);
  },

  createTask({ id, title, notes = '', category = 'Engineering', priority = 'Medium', plannedMins = 45, date, subject_id = null }) {
    const taskId = id || 'task_' + crypto.randomBytes(8).toString('hex');
    const taskDate = date || new Date().toISOString().split('T')[0];
    const now = new Date().toISOString();

    const maxOrderRow = db.prepare(`SELECT MAX(sort_order) AS max_order FROM tasks WHERE date = ?`).get(taskDate);
    const nextOrder = (maxOrderRow && maxOrderRow.max_order !== null) ? Number(maxOrderRow.max_order) + 1 : 0;

    db.prepare(`
      INSERT INTO tasks (id, title, notes, category, priority, status, planned_mins, actual_mins, date, sort_order, created_at, subject_id)
      VALUES (?, ?, ?, ?, ?, 'active', ?, 0, ?, ?, ?, ?)
    `).run(taskId, title.trim(), notes.trim(), category, priority, plannedMins, taskDate, nextOrder, now, subject_id);

    return this.getTaskById(taskId);
  },

  updateTask(id, fields) {
    const allowed = ['title', 'notes', 'category', 'priority', 'status', 'planned_mins', 'actual_mins', 'date', 'sort_order', 'completed_at', 'subject_id'];
    const setClauses = [];
    const params = [];

    for (const key of allowed) {
      if (fields[key] !== undefined) {
        setClauses.push(`${key} = ?`);
        params.push(fields[key]);
      }
    }

    if (setClauses.length === 0) return this.getTaskById(id);

    params.push(id);
    db.prepare(`UPDATE tasks SET ${setClauses.join(', ')} WHERE id = ?`).run(...params);
    return this.getTaskById(id);
  },

  deleteTask(id) {
    db.prepare(`DELETE FROM tasks WHERE id = ?`).run(id);
  },

  reorderTasks(taskIds) {
    const stmt = db.prepare(`UPDATE tasks SET sort_order = ? WHERE id = ?`);
    for (let i = 0; i < taskIds.length; i++) {
      stmt.run(i, taskIds[i]);
    }
  },

  // Time Logs
  addTimeLog({ taskId = null, durationSeconds, type = 'focus', startedAt, endedAt, notes = '' }) {
    const id = 'log_' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    const start = startedAt || new Date(Date.now() - durationSeconds * 1000).toISOString();
    const end = endedAt || now;

    db.prepare(`
      INSERT INTO time_logs (id, task_id, duration_seconds, type, started_at, ended_at, notes, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, taskId, durationSeconds, type, start, end, notes, now);

    // If attached to a task, increment its actual_mins
    if (taskId) {
      const addedMins = Math.round(durationSeconds / 60);
      if (addedMins > 0) {
        db.prepare(`UPDATE tasks SET actual_mins = actual_mins + ? WHERE id = ?`).run(addedMins, taskId);
      }
    }

    return db.prepare(`SELECT * FROM time_logs WHERE id = ?`).get(id);
  },

  getTimeLogs({ taskId, date, range } = {}) {
    let sql = `SELECT tl.*, t.title AS task_title, t.category AS task_category FROM time_logs tl LEFT JOIN tasks t ON t.id = tl.task_id WHERE 1=1`;
    const params = [];

    if (taskId) {
      sql += ` AND tl.task_id = ?`;
      params.push(taskId);
    }
    if (date) {
      sql += ` AND tl.started_at LIKE ?`;
      params.push(`${date}%`);
    }

    sql += ` ORDER BY tl.started_at DESC`;
    return db.prepare(sql).all(...params);
  },

  // Daily Standup & Journal
  getDailySummary(date) {
    return db.prepare(`SELECT * FROM daily_summaries WHERE date = ?`).get(date);
  },

  saveDailySummary(date, params = {}) {
    const summaryText = params.summary_text !== undefined ? params.summary_text : (params.summaryText || '');
    const mood = params.mood || 'productive';
    const blockers = params.blockers || '';
    const goalsTomorrow = params.goals_tomorrow !== undefined ? params.goals_tomorrow : (params.goalsTomorrow || '');
    const keyTakeaways = params.key_takeaways !== undefined ? params.key_takeaways : (params.keyTakeaways || '');
    const energyRating = params.energy_rating !== undefined ? parseInt(params.energy_rating) : 3;
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO daily_summaries (date, summary_text, mood, blockers, goals_tomorrow, key_takeaways, energy_rating, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(date) DO UPDATE SET
        summary_text = excluded.summary_text,
        mood = excluded.mood,
        blockers = excluded.blockers,
        goals_tomorrow = excluded.goals_tomorrow,
        key_takeaways = excluded.key_takeaways,
        energy_rating = excluded.energy_rating,
        updated_at = excluded.updated_at
    `).run(date, summaryText, mood, blockers, goalsTomorrow, keyTakeaways, energyRating, now, now);
    return this.getDailySummary(date);
  },

  generateDailyStandup(date) {
    const tasks = db.prepare(`SELECT * FROM tasks WHERE date = ? ORDER BY sort_order ASC, created_at ASC`).all(date);
    const completedTasks = tasks.filter(t => t.status === 'completed');
    const inProgressTasks = tasks.filter(t => t.status === 'active');

    const logs = db.prepare(`
      SELECT SUM(duration_seconds) AS total_seconds,
             SUM(CASE WHEN type = 'focus' THEN duration_seconds ELSE 0 END) AS focus_seconds
      FROM time_logs
      WHERE started_at LIKE ?
    `).get(`${date}%`);

    const totalSeconds = Number(logs.total_seconds || 0);
    const focusSeconds = Number(logs.focus_seconds || 0);
    const totalHours = (totalSeconds / 3600).toFixed(1);
    const focusHours = (focusSeconds / 3600).toFixed(1);

    const existingJournal = this.getDailySummary(date) || {};

    let markdown = `# 📋 Daily Standup — ${date}\n\n`;
    markdown += `**⏱️ Total Time Tracked:** ${totalHours}h (${focusHours}h Deep Focus)\n`;
    markdown += `**✅ Tasks Completed:** ${completedTasks.length}/${tasks.length}\n\n`;

    markdown += `### 🎯 Accomplished Today\n`;
    if (completedTasks.length === 0) {
      markdown += `- No tasks marked completed yet for today.\n`;
    } else {
      for (const t of completedTasks) {
        markdown += `- [x] **[${t.category}]** ${t.title} (${t.actual_mins}m logged / ${t.planned_mins}m planned)\n`;
        if (t.notes) markdown += `  - *Notes:* ${t.notes}\n`;
      }
    }

    markdown += `\n### ⏳ In Progress & Carry-over\n`;
    if (inProgressTasks.length === 0) {
      markdown += `- All planned tasks for today completed!\n`;
    } else {
      for (const t of inProgressTasks) {
        markdown += `- [ ] **[${t.category}]** ${t.title} (${t.actual_mins}m logged so far)\n`;
      }
    }

    if (existingJournal.blockers) {
      markdown += `\n### 🛑 Blockers & Obstacles\n${existingJournal.blockers}\n`;
    }

    if (existingJournal.goals_tomorrow) {
      markdown += `\n### 🚀 Goals for Tomorrow\n${existingJournal.goals_tomorrow}\n`;
    }

    return {
      date,
      markdown,
      totalHours,
      focusHours,
      completedCount: completedTasks.length,
      activeCount: inProgressTasks.length,
      mood: existingJournal.mood || 'productive'
    };
  },

  // Analytics & Dashboard Telemetry
  getAnalytics(range = '30d') {
    const now = new Date();
    let startDate;

    if (range === 'today') {
      startDate = now.toISOString().split('T')[0];
    } else if (range === '7d') {
      const d = new Date(now);
      d.setDate(now.getDate() - 6);
      startDate = d.toISOString().split('T')[0];
    } else if (range === '30d') {
      const d = new Date(now);
      d.setDate(now.getDate() - 29);
      startDate = d.toISOString().split('T')[0];
    } else {
      startDate = '1970-01-01';
    }

    // Total hours logged from time_logs
    const timeStats = db.prepare(`
      SELECT
        COALESCE(SUM(duration_seconds), 0) AS total_duration,
        COALESCE(SUM(CASE WHEN type = 'focus' THEN duration_seconds ELSE 0 END), 0) AS focus_duration
      FROM time_logs
      WHERE started_at >= ?
    `).get(startDate);

    const totalHours = (Number(timeStats.total_duration) / 3600).toFixed(1);
    const focusHours = (Number(timeStats.focus_duration) / 3600).toFixed(1);

    // Task completion metrics
    const taskStats = db.prepare(`
      SELECT
        COUNT(*) AS total_count,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_count,
        COALESCE(SUM(planned_mins), 0) AS total_planned_mins,
        COALESCE(SUM(actual_mins), 0) AS total_actual_mins
      FROM tasks
      WHERE date >= ?
    `).get(startDate);

    const totalTasks = Number(taskStats.total_count);
    const completedTasks = Number(taskStats.completed_count);
    const completionRate = totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 100) : 100;

    // Deep focus score: ratio of focus time + completion weight
    const deepFocusScore = totalTasks > 0
      ? Math.min(100, Math.round((completionRate * 0.5) + (Number(focusHours) > 0 ? 50 : 20)))
      : 85;

    // Consecutive active streak (up to 90 days back)
    const datesWithActivity = db.prepare(`
      SELECT DISTINCT date FROM tasks WHERE date >= date('now', '-90 days')
      UNION
      SELECT DISTINCT substr(started_at, 1, 10) as date FROM time_logs WHERE started_at >= date('now', '-90 days')
      ORDER BY date DESC
    `).all().map(r => r.date);

    let streak = 0;
    const checkDate = new Date();
    // Allow today or yesterday as start of streak
    const todayStr = checkDate.toISOString().split('T')[0];
    checkDate.setDate(checkDate.getDate() - 1);
    const yesterdayStr = checkDate.toISOString().split('T')[0];

    const hasToday = datesWithActivity.includes(todayStr);
    const hasYesterday = datesWithActivity.includes(yesterdayStr);

    if (hasToday || hasYesterday) {
      let cur = new Date();
      if (!hasToday && hasYesterday) {
        cur.setDate(cur.getDate() - 1);
      }
      while (true) {
        const s = cur.toISOString().split('T')[0];
        if (datesWithActivity.includes(s)) {
          streak++;
          cur.setDate(cur.getDate() - 1);
        } else {
          break;
        }
      }
    }

    // Category breakdown
    const categoryRows = db.prepare(`
      SELECT
        category,
        COALESCE(SUM(actual_mins), 0) AS total_mins,
        COUNT(*) AS task_count
      FROM tasks
      WHERE date >= ?
      GROUP BY category
    `).all(startDate);

    // 90-day activity heatmap
    const heatmapRows = db.prepare(`
      SELECT
        d.date,
        COALESCE(t.task_count, 0) as task_count,
        COALESCE(t.completed_count, 0) as completed_count,
        COALESCE(l.total_mins, 0) as total_mins
      FROM (
        SELECT date('now', '-' || (seq - 1) || ' days') AS date
        FROM (
          WITH RECURSIVE cnt(seq) AS (
            SELECT 1 UNION ALL SELECT seq + 1 FROM cnt WHERE seq < 91
          )
          SELECT seq FROM cnt
        )
      ) d
      LEFT JOIN (
        SELECT date, COUNT(*) as task_count, SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed_count
        FROM tasks
        WHERE date >= date('now', '-90 days')
        GROUP BY date
      ) t ON t.date = d.date
      LEFT JOIN (
        SELECT substr(started_at, 1, 10) as log_date, ROUND(SUM(duration_seconds) / 60.0) as total_mins
        FROM time_logs
        WHERE started_at >= date('now', '-90 days')
        GROUP BY log_date
      ) l ON l.log_date = d.date
      ORDER BY d.date ASC
    `).all();

    // Workload series (planned vs actual for 7 or 14 days)
    const daysBack = range === 'today' ? 1 : (range === '7d' ? 7 : 14);
    const workloadRows = db.prepare(`
      SELECT
        d.date,
        COALESCE(t.planned_hours, 0) as planned_hours,
        COALESCE(t.actual_hours, 0) as actual_hours
      FROM (
        SELECT date('now', '-' || (seq - 1) || ' days') AS date
        FROM (
          WITH RECURSIVE cnt(seq) AS (
            SELECT 1 UNION ALL SELECT seq + 1 FROM cnt WHERE seq < ?
          )
          SELECT seq FROM cnt
        )
      ) d
      LEFT JOIN (
        SELECT
          date,
          ROUND(SUM(planned_mins) / 60.0, 1) as planned_hours,
          ROUND(SUM(actual_mins) / 60.0, 1) as actual_hours
        FROM tasks
        GROUP BY date
      ) t ON t.date = d.date
      ORDER BY d.date ASC
    `).all(daysBack + 1);

    return {
      totalHours: Number(totalHours),
      focusHours: Number(focusHours),
      totalTasks,
      completedTasks,
      completionRate,
      deepFocusScore,
      streak,
      categories: categoryRows,
      heatmap: heatmapRows,
      workload: workloadRows
    };
  },

  // Settings
  getSettings() {
    const rows = db.prepare(`SELECT key, value FROM settings`).all();
    const map = {};
    for (const r of rows) map[r.key] = r.value;
    return map;
  },

  updateSettings(settingsObj) {
    const stmt = db.prepare(`
      INSERT INTO settings (key, value) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `);
    for (const [k, v] of Object.entries(settingsObj)) {
      stmt.run(k, String(v));
    }
    return this.getSettings();
  },

  // Classes (be10x & nxtwave)
  getClasses(platform) {
    if (platform && platform !== 'all') {
      return db.prepare(`SELECT * FROM classes WHERE platform = ? ORDER BY created_at DESC`).all(platform);
    }
    return db.prepare(`SELECT * FROM classes ORDER BY created_at DESC`).all();
  },
  createClass({ platform, title, module = '', status = 'pending', notes = '', date }) {
    const id = 'cls_' + crypto.randomBytes(8).toString('hex');
    const classDate = date || new Date().toISOString().split('T')[0];
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO classes (id, platform, title, module, status, notes, date, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, platform, title.trim(), module.trim(), status, notes.trim(), classDate, now);
    return db.prepare(`SELECT * FROM classes WHERE id = ?`).get(id);
  },
  updateClass(id, fields) {
    const allowed = ['title', 'module', 'status', 'notes', 'date'];
    const setClauses = [];
    const params = [];
    for (const key of allowed) {
      if (fields[key] !== undefined) {
        setClauses.push(`${key} = ?`);
        params.push(fields[key]);
      }
    }
    if (setClauses.length === 0) return db.prepare(`SELECT * FROM classes WHERE id = ?`).get(id);
    params.push(id);
    db.prepare(`UPDATE classes SET ${setClauses.join(', ')} WHERE id = ?`).run(...params);
    return db.prepare(`SELECT * FROM classes WHERE id = ?`).get(id);
  },
  deleteClass(id) {
    db.prepare(`DELETE FROM classes WHERE id = ?`).run(id);
  },

  // Workouts
  getWorkouts(date) {
    if (date) {
      return db.prepare(`SELECT * FROM workouts WHERE date = ? ORDER BY created_at DESC`).all(date);
    }
    return db.prepare(`SELECT * FROM workouts ORDER BY created_at DESC`).all();
  },
  createWorkout({ exercise, category = 'Push', sets = 3, reps = '12', weight = 'Bodyweight', status = 'pending', date }) {
    const id = 'wrk_' + crypto.randomBytes(8).toString('hex');
    const wDate = date || new Date().toISOString().split('T')[0];
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO workouts (id, exercise, category, sets, reps, weight, status, date, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, exercise.trim(), category, sets, reps, weight, status, wDate, now);
    return db.prepare(`SELECT * FROM workouts WHERE id = ?`).get(id);
  },
  updateWorkout(id, fields) {
    const allowed = ['exercise', 'category', 'sets', 'reps', 'weight', 'status', 'date'];
    const setClauses = [];
    const params = [];
    for (const key of allowed) {
      if (fields[key] !== undefined) {
        setClauses.push(`${key} = ?`);
        params.push(fields[key]);
      }
    }
    if (setClauses.length === 0) return db.prepare(`SELECT * FROM workouts WHERE id = ?`).get(id);
    params.push(id);
    db.prepare(`UPDATE workouts SET ${setClauses.join(', ')} WHERE id = ?`).run(...params);
    return db.prepare(`SELECT * FROM workouts WHERE id = ?`).get(id);
  },
  deleteWorkout(id) {
    db.prepare(`DELETE FROM workouts WHERE id = ?`).run(id);
  },

  // BTech Subjects & CGPA
  getBTechSubjects(semester) {
    if (semester && semester !== 'all') {
      return db.prepare(`SELECT * FROM btech_subjects WHERE semester = ? ORDER BY code ASC`).all(semester);
    }
    return db.prepare(`SELECT * FROM btech_subjects ORDER BY semester ASC, code ASC`).all();
  },
  createBTechSubject({ subject_name, code, credits = 3, internal_marks = 0, external_marks = 0, grade = 'A', status = 'ongoing', semester = 5 }) {
    const id = 'sub_' + crypto.randomBytes(8).toString('hex');
    db.prepare(`
      INSERT INTO btech_subjects (id, subject_name, code, credits, internal_marks, external_marks, grade, status, semester)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, subject_name.trim(), code.trim(), credits, internal_marks, external_marks, grade, status, parseInt(semester) || 5);
    return db.prepare(`SELECT * FROM btech_subjects WHERE id = ?`).get(id);
  },
  updateBTechSubject(id, fields) {
    const allowed = ['subject_name', 'code', 'credits', 'internal_marks', 'external_marks', 'grade', 'status', 'semester'];
    const setClauses = [];
    const params = [];
    for (const key of allowed) {
      if (fields[key] !== undefined) {
        setClauses.push(`${key} = ?`);
        params.push(fields[key]);
      }
    }
    if (setClauses.length === 0) return db.prepare(`SELECT * FROM btech_subjects WHERE id = ?`).get(id);
    params.push(id);
    db.prepare(`UPDATE btech_subjects SET ${setClauses.join(', ')} WHERE id = ?`).run(...params);
    return db.prepare(`SELECT * FROM btech_subjects WHERE id = ?`).get(id);
  },
  deleteBTechSubject(id) {
    db.prepare(`DELETE FROM btech_subjects WHERE id = ?`).run(id);
  },

  // Coding Practice
  getCodingPractice() {
    return db.prepare(`SELECT * FROM coding_practice ORDER BY date DESC`).all();
  },
  createCodingPractice({ platform = 'LeetCode', problem_title, difficulty = 'Medium', status = 'solved', date, notes = '' }) {
    const id = 'cod_' + crypto.randomBytes(8).toString('hex');
    const cDate = date || new Date().toISOString().split('T')[0];
    db.prepare(`
      INSERT INTO coding_practice (id, platform, problem_title, difficulty, status, date, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, platform, problem_title.trim(), difficulty, status, cDate, notes.trim());
    return db.prepare(`SELECT * FROM coding_practice WHERE id = ?`).get(id);
  },
  deleteCodingPractice(id) {
    db.prepare(`DELETE FROM coding_practice WHERE id = ?`).run(id);
  },

  // Subject Works
  getSubjectWorks(subjectId) {
    return db.prepare(`SELECT * FROM subject_works WHERE subject_id = ? ORDER BY deadline ASC`).all(subjectId);
  },
  createSubjectWork({ subjectId, title, type = 'Assignment', status = 'pending', deadline = '' }) {
    const id = 'work_' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO subject_works (id, subject_id, title, type, status, deadline, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, subjectId, title.trim(), type, status, deadline, now);
    return db.prepare(`SELECT * FROM subject_works WHERE id = ?`).get(id);
  },
  updateSubjectWork(id, fields) {
    const allowed = ['title', 'type', 'status', 'deadline'];
    const setClauses = [];
    const params = [];
    for (const key of allowed) {
      if (fields[key] !== undefined) {
        setClauses.push(`${key} = ?`);
        params.push(fields[key]);
      }
    }
    if (setClauses.length === 0) return db.prepare(`SELECT * FROM subject_works WHERE id = ?`).get(id);
    params.push(id);
    db.prepare(`UPDATE subject_works SET ${setClauses.join(', ')} WHERE id = ?`).run(...params);
    return db.prepare(`SELECT * FROM subject_works WHERE id = ?`).get(id);
  },
  deleteSubjectWork(id) {
    db.prepare(`DELETE FROM subject_works WHERE id = ?`).run(id);
  },

  // Clear & Seed Data
  clearWorkData() {
    db.prepare(`DELETE FROM time_logs`).run();
    db.prepare(`DELETE FROM tasks`).run();
    db.prepare(`DELETE FROM daily_summaries`).run();
    db.prepare(`DELETE FROM classes`).run();
    db.prepare(`DELETE FROM workouts`).run();
    db.prepare(`DELETE FROM btech_subjects`).run();
    db.prepare(`DELETE FROM coding_practice`).run();
    db.prepare(`DELETE FROM subject_works`).run();
  },

  seedSampleData() {
    this.clearWorkData();

    const categories = ['Engineering', 'Product', 'Design', 'Deep Work', 'Admin'];
    const priorities = ['High', 'Medium', 'Low'];
    const sampleTitles = {
      'Engineering': [
        'Implement Redis cache layer for API gateway',
        'Refactor authentication middleware to scrypt v2',
        'Fix memory leak in distributed worker queue',
        'Write integration tests for payment webhooks',
        'Database schema migration for parcel audit logs',
        'Optimize SQLite query latency and WAL configuration'
      ],
      'Product': [
        'Draft Q4 product roadmap specs',
        'Review user churn analytics & teardown',
        'Synthesize customer feedback interviews',
        'Define KPI telemetry for checkout funnel',
        'Prioritize sprint backlog with engineering leads'
      ],
      'Design': [
        'Create high-fidelity dark mode tokens in Figma',
        'Design mobile responsive drawer navigation',
        'Accessibility audit: contrast ratios & focus rings',
        'Micro-animations for task completion states'
      ],
      'Deep Work': [
        'Write RFC for event-driven telemetry architecture',
        'Deep profile Node.js garbage collection pauses',
        'Competitive teardown of workflow automation engines',
        'Draft system design document for offline sync'
      ],
      'Admin': [
        'Weekly engineering team sync & standup',
        'Inbox zero & triage GitHub security dependabot PRs',
        'Update documentation for developer onboarding',
        'Review cloud infrastructure billing alerts'
      ]
    };

    const estimates = [15, 25, 30, 45, 60, 90, 120];
    const now = new Date();

    const insertTask = db.prepare(`
      INSERT INTO tasks (id, title, notes, category, priority, status, planned_mins, actual_mins, date, sort_order, created_at, completed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertLog = db.prepare(`
      INSERT INTO time_logs (id, task_id, duration_seconds, type, started_at, ended_at, notes, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // Generate 14 days of realistic activity
    for (let i = 13; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(now.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      const isWeekend = (d.getDay() === 0 || d.getDay() === 6);
      const taskCount = isWeekend ? Math.floor(Math.random() * 2) + 1 : Math.floor(Math.random() * 3) + 3;

      for (let j = 0; j < taskCount; j++) {
        const cat = categories[Math.floor(Math.random() * categories.length)];
        const titles = sampleTitles[cat];
        const title = titles[Math.floor(Math.random() * titles.length)];
        const priority = priorities[Math.floor(Math.random() * priorities.length)];
        const planned = estimates[Math.floor(Math.random() * estimates.length)];
        const isPast = i > 0;
        const isCompleted = isPast ? Math.random() > 0.15 : Math.random() > 0.5;
        const variance = (Math.random() * 0.4) - 0.2;
        const actual = isCompleted ? Math.max(15, Math.round(planned * (1 + variance))) : Math.floor(planned * 0.4);

        const taskId = 'task_' + crypto.randomBytes(8).toString('hex');
        const createdIso = new Date(d.getTime() + j * 3600000).toISOString();
        const completedIso = isCompleted ? new Date(d.getTime() + (j + 1) * 3600000).toISOString() : null;

        insertTask.run(
          taskId,
          title,
          isCompleted ? 'Accomplished during deep work session.' : '',
          cat,
          priority,
          isCompleted ? 'completed' : 'active',
          planned,
          actual,
          dateStr,
          j,
          createdIso,
          completedIso
        );

        if (actual > 0) {
          const logId = 'log_' + crypto.randomBytes(8).toString('hex');
          const logDurationSec = actual * 60;
          insertLog.run(
            logId,
            taskId,
            logDurationSec,
            'focus',
            createdIso,
            new Date(new Date(createdIso).getTime() + logDurationSec * 1000).toISOString(),
            'Focus session',
            createdIso
          );
        }
      }
    }
  }
};

module.exports = dbApi;
