const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const url = require('node:url');

const db = require('./db.js');
const auth = require('./auth.js');

const PORT = process.env.PORT || 3000;

const MIME_TYPES = {
  '.html': 'text/html; charset=UTF-8',
  '.js': 'text/javascript; charset=UTF-8',
  '.css': 'text/css; charset=UTF-8',
  '.json': 'application/json; charset=UTF-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// -----------------------------------------------------------------------------
// Request Helpers
// -----------------------------------------------------------------------------
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      // 1MB request body limit
      if (body.length > 1024 * 1024) {
        req.destroy();
        reject(new Error('Payload Too Large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', err => reject(err));
  });
}

function sendJson(res, statusCode, data, headers = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=UTF-8',
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    ...headers
  });
  res.end(JSON.stringify(data));
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || '';
}

// -----------------------------------------------------------------------------
// HTTP Server & Router
// -----------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method.toUpperCase();
  const clientIp = getClientIp(req);
  const userAgent = req.headers['user-agent'] || '';

  // ---------------------------------------------------------------------------
  // API Route Handling
  // ---------------------------------------------------------------------------
  if (pathname.startsWith('/api/')) {
    try {
      // 1. Auth Status (public)
      if (pathname === '/api/auth/status' && method === 'GET') {
        const status = auth.getAuthStatus(req);
        return sendJson(res, 200, status);
      }

      // 2. First-Launch Setup (public until initial user created)
      if (pathname === '/api/auth/setup' && method === 'POST') {
        const body = await parseBody(req);
        const result = await auth.setupOwner(body.username, body.password, clientIp);
        if (result.error) {
          return sendJson(res, result.status || 400, { error: result.error });
        }
        const cookie = `toji_session=${result.token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${30 * 24 * 3600}`;
        return sendJson(res, 200, result, { 'Set-Cookie': cookie });
      }

      // 3. Login (public)
      if (pathname === '/api/auth/login' && method === 'POST') {
        const body = await parseBody(req);
        const result = await auth.login(body.password, clientIp, userAgent);
        if (result.error) {
          return sendJson(res, result.status || 401, { error: result.error });
        }
        const cookie = `toji_session=${result.token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${30 * 24 * 3600}`;
        return sendJson(res, 200, result, { 'Set-Cookie': cookie });
      }

      // 4. Logout
      if (pathname === '/api/auth/logout' && method === 'POST') {
        auth.logout(req);
        const cookie = `toji_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
        return sendJson(res, 200, { success: true }, { 'Set-Cookie': cookie });
      }

      // -----------------------------------------------------------------------
      // Protected Routes — Verify Authentication
      // -----------------------------------------------------------------------
      const user = auth.requireAuth(req, res);
      if (!user) return; // Response sent by requireAuth (401)

      // Change Password
      if (pathname === '/api/auth/change-password' && method === 'POST') {
        const body = await parseBody(req);
        const result = auth.changePassword(user.userId, body.currentPassword, body.newPassword);
        if (result.error) {
          return sendJson(res, result.status || 400, { error: result.error });
        }
        const cookie = `toji_session=${result.token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${30 * 24 * 3600}`;
        return sendJson(res, 200, { success: true }, { 'Set-Cookie': cookie });
      }

      // Tasks CRUD
      if (pathname === '/api/tasks' && method === 'GET') {
        const tasks = db.getTasks({
          date: parsedUrl.query.date,
          status: parsedUrl.query.status,
          category: parsedUrl.query.category,
          search: parsedUrl.query.search
        });
        return sendJson(res, 200, { tasks });
      }

      if (pathname === '/api/tasks' && method === 'POST') {
        const body = await parseBody(req);
        if (!body.title || !body.title.trim()) {
          return sendJson(res, 400, { error: 'Task title is required.' });
        }
        const task = db.createTask(body);
        return sendJson(res, 201, { task });
      }

      if (pathname === '/api/tasks/reorder' && method === 'POST') {
        const body = await parseBody(req);
        if (Array.isArray(body.taskIds)) {
          db.reorderTasks(body.taskIds);
        }
        return sendJson(res, 200, { success: true });
      }

      // Matches /api/tasks/:id/log-time
      const logTimeMatch = pathname.match(/^\/api\/tasks\/([^/]+)\/log-time$/);
      if (logTimeMatch && method === 'POST') {
        const taskId = logTimeMatch[1];
        const body = await parseBody(req);
        const durationSeconds = Number(body.durationSeconds) || 0;
        const log = db.addTimeLog({
          taskId,
          durationSeconds,
          type: body.type || 'focus',
          notes: body.notes || ''
        });
        const updatedTask = db.getTaskById(taskId);
        return sendJson(res, 200, { log, task: updatedTask });
      }

      // Matches /api/tasks/:id
      const taskMatch = pathname.match(/^\/api\/tasks\/([^/]+)$/);
      if (taskMatch) {
        const taskId = taskMatch[1];
        if (method === 'GET') {
          const task = db.getTaskById(taskId);
          if (!task) return sendJson(res, 404, { error: 'Task not found' });
          return sendJson(res, 200, { task });
        }
        if (method === 'PUT') {
          const body = await parseBody(req);
          const task = db.updateTask(taskId, body);
          return sendJson(res, 200, { task });
        }
        if (method === 'DELETE') {
          db.deleteTask(taskId);
          return sendJson(res, 200, { success: true, id: taskId });
        }
      }

      // Time Logs
      if (pathname === '/api/timelogs' && method === 'GET') {
        const logs = db.getTimeLogs({
          taskId: parsedUrl.query.taskId,
          date: parsedUrl.query.date
        });
        return sendJson(res, 200, { logs });
      }

      if (pathname === '/api/timelogs' && method === 'POST') {
        const body = await parseBody(req);
        const log = db.addTimeLog(body);
        return sendJson(res, 201, { log });
      }

      // Daily Standup & Journal
      const journalMatch = pathname.match(/^\/api\/journal\/([^/]+)$/);
      if (journalMatch) {
        const date = journalMatch[1];
        if (method === 'GET') {
          const summary = db.getDailySummary(date) || { date, summary_text: '', mood: 'productive', blockers: '', goals_tomorrow: '' };
          return sendJson(res, 200, { summary });
        }
        if (method === 'PUT') {
          const body = await parseBody(req);
          const summary = db.saveDailySummary(date, body);
          return sendJson(res, 200, { summary });
        }
      }

      const standupGenerateMatch = pathname.match(/^\/api\/journal\/generate\/([^/]+)$/);
      if (standupGenerateMatch && method === 'POST') {
        const date = standupGenerateMatch[1];
        const standup = db.generateDailyStandup(date);
        return sendJson(res, 200, { standup });
      }

      // Analytics
      if (pathname === '/api/analytics' && method === 'GET') {
        const range = parsedUrl.query.range || '30d';
        const analytics = db.getAnalytics(range);
        return sendJson(res, 200, { analytics });
      }

      // Settings
      if (pathname === '/api/settings' && method === 'GET') {
        const settings = db.getSettings();
        return sendJson(res, 200, { settings });
      }

      if (pathname === '/api/settings' && method === 'PUT') {
        const body = await parseBody(req);
        const settings = db.updateSettings(body.settings || body);
        return sendJson(res, 200, { settings });
      }

      // Classes (be10x & nxtwave)
      if (pathname === '/api/classes' && method === 'GET') {
        const classes = db.getClasses(parsedUrl.query.platform);
        return sendJson(res, 200, { classes });
      }
      if (pathname === '/api/classes' && method === 'POST') {
        const body = await parseBody(req);
        if (!body.title || !body.title.trim()) {
          return sendJson(res, 400, { error: 'Class title is required.' });
        }
        const cls = db.createClass(body);
        return sendJson(res, 201, { class: cls });
      }
      const classMatch = pathname.match(/^\/api\/classes\/([^/]+)$/);
      if (classMatch) {
        const clsId = classMatch[1];
        if (method === 'PUT') {
          const body = await parseBody(req);
          const cls = db.updateClass(clsId, body);
          return sendJson(res, 200, { class: cls });
        }
        if (method === 'DELETE') {
          db.deleteClass(clsId);
          return sendJson(res, 200, { success: true, id: clsId });
        }
      }

      // Workouts
      if (pathname === '/api/workouts' && method === 'GET') {
        const workouts = db.getWorkouts(parsedUrl.query.date);
        return sendJson(res, 200, { workouts });
      }
      if (pathname === '/api/workouts' && method === 'POST') {
        const body = await parseBody(req);
        if (!body.exercise || !body.exercise.trim()) {
          return sendJson(res, 400, { error: 'Exercise name is required.' });
        }
        const wrk = db.createWorkout(body);
        return sendJson(res, 201, { workout: wrk });
      }
      const workoutMatch = pathname.match(/^\/api\/workouts\/([^/]+)$/);
      if (workoutMatch) {
        const wrkId = workoutMatch[1];
        if (method === 'PUT') {
          const body = await parseBody(req);
          const wrk = db.updateWorkout(wrkId, body);
          return sendJson(res, 200, { workout: wrk });
        }
        if (method === 'DELETE') {
          db.deleteWorkout(wrkId);
          return sendJson(res, 200, { success: true, id: wrkId });
        }
      }

      // BTech Subjects
      if (pathname === '/api/btech' && method === 'GET') {
        const subjects = db.getBTechSubjects();
        return sendJson(res, 200, { subjects });
      }
      if (pathname === '/api/btech' && method === 'POST') {
        const body = await parseBody(req);
        const sub = db.createBTechSubject(body);
        return sendJson(res, 201, { subject: sub });
      }
      const btechMatch = pathname.match(/^\/api\/btech\/([^/]+)$/);
      if (btechMatch) {
        const subId = btechMatch[1];
        if (method === 'PUT') {
          const body = await parseBody(req);
          const sub = db.updateBTechSubject(subId, body);
          return sendJson(res, 200, { subject: sub });
        }
        if (method === 'DELETE') {
          db.deleteBTechSubject(subId);
          return sendJson(res, 200, { success: true, id: subId });
        }
      }

      const btechWorksMatch = pathname.match(/^\/api\/btech\/([^/]+)\/works$/);
      if (btechWorksMatch) {
        const subjectId = btechWorksMatch[1];
        if (method === 'GET') {
          const works = db.getSubjectWorks(subjectId);
          return sendJson(res, 200, { works });
        }
        if (method === 'POST') {
          const body = await parseBody(req);
          const work = db.createSubjectWork({ ...body, subjectId });
          return sendJson(res, 201, { work });
        }
      }

      const workMatch = pathname.match(/^\/api\/works\/([^/]+)$/);
      if (workMatch) {
        const workId = workMatch[1];
        if (method === 'PUT') {
          const body = await parseBody(req);
          const work = db.updateSubjectWork(workId, body);
          return sendJson(res, 200, { work });
        }
        if (method === 'DELETE') {
          db.deleteSubjectWork(workId);
          return sendJson(res, 200, { success: true, id: workId });
        }
      }

      // Coding Practice
      if (pathname === '/api/coding' && method === 'GET') {
        const coding = db.getCodingPractice();
        return sendJson(res, 200, { coding });
      }
      if (pathname === '/api/coding' && method === 'POST') {
        const body = await parseBody(req);
        const cod = db.createCodingPractice(body);
        return sendJson(res, 201, { coding: cod });
      }
      const codingMatch = pathname.match(/^\/api\/coding\/([^/]+)$/);
      if (codingMatch) {
        const codId = codingMatch[1];
        if (method === 'DELETE') {
          db.deleteCodingPractice(codId);
          return sendJson(res, 200, { success: true, id: codId });
        }
      }

      // Export
      if (pathname === '/api/export/json' && method === 'GET') {
        const tasks = db.getTasks();
        const logs = db.getTimeLogs();
        const settings = db.getSettings();
        const dump = {
          exported_at: new Date().toISOString(),
          version: '2.0.0',
          tasks,
          logs,
          settings
        };
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Disposition': `attachment; filename="toji-backup-${new Date().toISOString().split('T')[0]}.json"`
        });
        return res.end(JSON.stringify(dump, null, 2));
      }

      if (pathname === '/api/export/csv' && method === 'GET') {
        const tasks = db.getTasks();
        const headers = ['ID', 'Title', 'Notes', 'Category', 'Priority', 'PlannedMinutes', 'ActualMinutes', 'Date', 'Status', 'CreatedAt', 'CompletedAt'];
        const rows = tasks.map(t => [
          t.id,
          `"${(t.title || '').replace(/"/g, '""')}"`,
          `"${(t.notes || '').replace(/"/g, '""')}"`,
          t.category,
          t.priority,
          t.planned_mins,
          t.actual_mins,
          t.date,
          t.status,
          t.created_at,
          t.completed_at || ''
        ]);
        const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
        res.writeHead(200, {
          'Content-Type': 'text/csv; charset=UTF-8',
          'Content-Disposition': `attachment; filename="toji-work-log-${new Date().toISOString().split('T')[0]}.csv"`
        });
        return res.end(csv);
      }

      // Sample & Clear Data
      if (pathname === '/api/sample-data' && method === 'POST') {
        db.seedSampleData();
        return sendJson(res, 200, { success: true, message: '14 days of realistic sample data seeded.' });
      }

      if (pathname === '/api/clear-data' && method === 'POST') {
        db.clearWorkData();
        return sendJson(res, 200, { success: true, message: 'All work records purged.' });
      }

      // Unmatched API endpoint
      return sendJson(res, 404, { error: 'API route not found' });

    } catch (err) {
      console.error('API Error:', err);
      return sendJson(res, 500, { error: 'Internal Server Error', message: err.message });
    }
  }

  // ---------------------------------------------------------------------------
  // Static File Serving
  // ---------------------------------------------------------------------------
  let reqUrl = pathname;
  if (reqUrl === '/' || reqUrl === '') reqUrl = '/index.html';

  // Security: prevent path traversal
  const safePath = path.normalize(reqUrl).replace(/^(\.\.[/\\])+/, '');
  let filePath = path.join(__dirname, safePath);
  if (!fs.existsSync(filePath)) {
    const publicPath = path.join(__dirname, 'public', safePath);
    if (fs.existsSync(publicPath)) {
      filePath = publicPath;
    }
  }

  if (!filePath.startsWith(__dirname)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('403 Forbidden');
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': 'no-cache'
      });
      res.end(content);
    }
  });
});

if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY) {
  module.exports = server;
} else {
  server.listen(PORT, () => {
    console.log(`🚀 Toji Full-Stack Work Tracker running at http://localhost:${PORT}/`);
  });
}
