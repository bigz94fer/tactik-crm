// Tactik CRM API - Cloudflare Pages Function with D1
// Handles auth and CRUD for deals, activities, call logs, LinkedIn leads

const JWT_SECRET = 'tactik-crm-jwt-secret-2026-secure';

// ─── CORS ───
function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };
}

function jsonResp(data, status = 200, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(request) },
  });
}

// ─── PASSWORD HASHING (SHA-256) ───
async function hashPassword(password) {
  const data = new TextEncoder().encode(password + '_tactik_salt_2026');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, hash) {
  return (await hashPassword(password)) === hash;
}

// ─── JWT ───
async function createToken(userId, username, role) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
  const payload = btoa(JSON.stringify({
    sub: userId, username, role,
    exp: Math.floor(Date.now() / 1000) + 86400 * 7,
  })).replace(/=/g, '');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${payload}`));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, '');
  return `${header}.${payload}.${sigB64}`;
}

async function verifyToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, payload, sig] = parts;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(`${header}.${payload}`));
    if (!valid) return null;
    const data = JSON.parse(atob(payload));
    if (data.exp < Math.floor(Date.now() / 1000)) return null;
    return data;
  } catch { return null; }
}

async function verifyAuth(request) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return { error: 'No token' };
  const data = await verifyToken(auth.slice(7));
  if (!data) return { error: 'Invalid token' };
  return { user: { id: data.sub, username: data.username, role: data.role } };
}

// ─── MAIN HANDLER ───
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(request) });
  }

  try {
    // ─── AUTH ROUTES (no token) ───
    if (path === '/api/auth/setup' && method === 'POST') {
      const existing = await env.DB.prepare('SELECT id FROM users WHERE role = ?').bind('admin').first();
      if (existing) return jsonResp({ error: 'Setup already done' }, 400, request);
      const body = await request.json();
      const username = body.username || 'admin';
      const password = body.password;
      if (!password || password.length < 4) return jsonResp({ error: 'Password min 4 chars' }, 400, request);
      const hash = await hashPassword(password);
      const id = 'u_' + Date.now();
      await env.DB.prepare('INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)').bind(id, username, hash, 'admin', new Date().toISOString()).run();
      return jsonResp({ success: true, message: 'Admin created. Log in now.' }, 200, request);
    }

    if (path === '/api/auth/login' && method === 'POST') {
      const body = await request.json();
      const { username, password } = body;
      if (!username || !password) return jsonResp({ error: 'Username and password required' }, 400, request);
      const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
      if (!user) return jsonResp({ error: 'Invalid credentials' }, 401, request);
      if (!(await verifyPassword(password, user.password_hash))) return jsonResp({ error: 'Invalid credentials' }, 401, request);
      const token = await createToken(user.id, user.username, user.role);
      return jsonResp({ token, user: { id: user.id, username: user.username, role: user.role } }, 200, request);
    }

    if (path === '/api/auth/change-password' && method === 'POST') {
      const auth = await verifyAuth(request);
      if (auth.error) return jsonResp(auth, 401, request);
      const body = await request.json();
      const dbUser = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(auth.user.id).first();
      if (!(await verifyPassword(body.currentPassword, dbUser.password_hash))) return jsonResp({ error: 'Wrong password' }, 400, request);
      const hash = await hashPassword(body.newPassword);
      await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(hash, auth.user.id).run();
      return jsonResp({ success: true }, 200, request);
    }

    // ─── ALL OTHER /api/ ROUTES REQUIRE AUTH ───
    if (path.startsWith('/api/')) {
      const auth = await verifyAuth(request);
      if (auth.error) return jsonResp(auth, 401, request);

      // ─── GET /api/deals ───
      if (path === '/api/deals' && method === 'GET') {
        const deals = await env.DB.prepare('SELECT * FROM deals ORDER BY createdAt DESC').all();
        const callLogs = await env.DB.prepare('SELECT * FROM call_log').all();
        const callMap = {};
        for (const cl of callLogs.results) {
          if (!callMap[cl.deal_id]) callMap[cl.deal_id] = [];
          callMap[cl.deal_id].push(cl);
        }
        const result = deals.results.map(d => ({ ...d, callLog: callMap[d.id] || [] }));
        return jsonResp(result, 200, request);
      }

      // ─── POST /api/deals (create) ───
      if (path === '/api/deals' && method === 'POST') {
        const body = await request.json();
        const id = body.id || ('d_' + Date.now());
        const now = new Date().toISOString().split('T')[0];
        await env.DB.prepare(`INSERT INTO deals (id, company, contact, phone, email, value, stage, enquiryType, source, outcome, prob, brand, owner, dateContacted, followUpDate, followUpNum, dateClosed, daysToClose, nextAction, nextActionDate, closeDate, notes, createdAt, updatedAt)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
          id, body.company||'', body.contact||'', body.phone||'', body.email||'',
          body.value||0, body.stage||'Lead', body.enquiryType||'Website Design',
          body.source||'Networking', body.outcome||'Pending', body.prob||10,
          body.brand||'Tactik', body.owner||'Udara',
          body.dateContacted||'', body.followUpDate||'', body.followUpNum||0,
          body.dateClosed||'', body.daysToClose||0, body.nextAction||'',
          body.nextActionDate||'', body.closeDate||'', body.notes||'',
          body.createdAt||now, body.updatedAt||now
        ).run();
        // Audit log
        await env.DB.prepare('INSERT INTO audit_log (id, action, table_name, record_id, data, username, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime(\'now\'))').bind('audit_' + Date.now(), 'create', 'deals', id, JSON.stringify({company: body.company, value: body.value, stage: body.stage}), auth.user.username || '').run();
        if (body.callLog) {
          await env.DB.prepare('DELETE FROM call_log WHERE deal_id = ?').bind(id).run();
          for (const cl of body.callLog) {
            const clId = cl.id || ('cl_' + Date.now() + '_' + Math.random().toString(36).slice(2,6));
            await env.DB.prepare('INSERT INTO call_log (id, deal_id, date, time, rep, type, note) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(
              clId, id, cl.date||'', cl.time||'', cl.rep||'', cl.type||'Call', cl.note||'').run();
          }
        }
        return jsonResp({ success: true, id }, 200, request);
      }

      // ─── POST /api/deals/bulk ───
      if (path === '/api/deals/bulk' && method === 'POST') {
        const body = await request.json();
        if (!Array.isArray(body.deals)) return jsonResp({ error: 'deals array required' }, 400, request);
        // SAFETY: No prune on bulk sync — only upsert. Explicit DELETE /api/deals/:id for removals.
        // Previous prune logic caused data loss when empty arrays were sent.
        let inserted = 0, updated = 0;
        // Audit log — bulk sync
        await env.DB.prepare('INSERT INTO audit_log (id, action, table_name, record_id, data, username, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime(\'now\'))').bind('audit_' + Date.now(), 'bulk_sync', 'deals', 'batch', JSON.stringify({count: body.deals.length}), auth.user.username || '').run();
        for (const d of body.deals) {
          const id = d.id || ('d_' + Date.now() + '_' + Math.random().toString(36).slice(2,6));
          const existing = await env.DB.prepare('SELECT id FROM deals WHERE id = ?').bind(id).first();
          if (existing) {
            await env.DB.prepare(`UPDATE deals SET company=?, contact=?, phone=?, email=?, value=?, stage=?, enquiryType=?, source=?, outcome=?, prob=?, brand=?, owner=?, dateContacted=?, followUpDate=?, followUpNum=?, dateClosed=?, daysToClose=?, nextAction=?, nextActionDate=?, closeDate=?, notes=?, updatedAt=? WHERE id=?`).bind(
              d.company||'', d.contact||'', d.phone||'', d.email||'',
              d.value||0, d.stage||'Lead', d.enquiryType||'Website Design',
              d.source||'Networking', d.outcome||'Pending', d.prob||10,
              d.brand||'Tactik', d.owner||'Udara',
              d.dateContacted||'', d.followUpDate||'', d.followUpNum||0,
              d.dateClosed||'', d.daysToClose||0, d.nextAction||'',
              d.nextActionDate||'', d.closeDate||'', d.notes||'',
              d.updatedAt||new Date().toISOString().split('T')[0], id
            ).run();
            updated++;
          } else {
            await env.DB.prepare(`INSERT INTO deals (id, company, contact, phone, email, value, stage, enquiryType, source, outcome, prob, brand, owner, dateContacted, followUpDate, followUpNum, dateClosed, daysToClose, nextAction, nextActionDate, closeDate, notes, createdAt, updatedAt)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
              id, d.company||'', d.contact||'', d.phone||'', d.email||'',
              d.value||0, d.stage||'Lead', d.enquiryType||'Website Design',
              d.source||'Networking', d.outcome||'Pending', d.prob||10,
              d.brand||'Tactik', d.owner||'Udara',
              d.dateContacted||'', d.followUpDate||'', d.followUpNum||0,
              d.dateClosed||'', d.daysToClose||0, d.nextAction||'',
              d.nextActionDate||'', d.closeDate||'', d.notes||'',
              d.createdAt||new Date().toISOString().split('T')[0], d.updatedAt||new Date().toISOString().split('T')[0]
            ).run();
            inserted++;
          }
          if (d.callLog && Array.isArray(d.callLog)) {
            await env.DB.prepare('DELETE FROM call_log WHERE deal_id = ?').bind(id).run();
            for (const cl of d.callLog) {
              const clId = cl.id || ('cl_' + Date.now() + '_' + Math.random().toString(36).slice(2,6));
              await env.DB.prepare('INSERT INTO call_log (id, deal_id, date, time, rep, type, note) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(
                clId, id, cl.date||'', cl.time||'', cl.rep||'', cl.type||'Call', cl.note||'').run();
            }
          }
        }
        return jsonResp({ success: true, inserted, updated }, 200, request);
      }

      // ─── PUT /api/deals (update) ───
      if (path === '/api/deals' && method === 'PUT') {
        const body = await request.json();
        if (!body.id) return jsonResp({ error: 'id required' }, 400, request);
        const now = new Date().toISOString().split('T')[0];
        await env.DB.prepare(`UPDATE deals SET company=?, contact=?, phone=?, email=?, value=?, stage=?, enquiryType=?, source=?, outcome=?, prob=?, brand=?, owner=?, dateContacted=?, followUpDate=?, followUpNum=?, dateClosed=?, daysToClose=?, nextAction=?, nextActionDate=?, closeDate=?, notes=?, updatedAt=? WHERE id=?`).bind(
          body.company??'', body.contact??'', body.phone??'', body.email??'',
          body.value??0, body.stage??'Lead', body.enquiryType??'Website Design',
          body.source??'Networking', body.outcome??'Pending', body.prob??10,
          body.brand??'Tactik', body.owner??'Udara',
          body.dateContacted??'', body.followUpDate??'', body.followUpNum??0,
          body.dateClosed??'', body.daysToClose??0, body.nextAction??'',
          body.nextActionDate??'', body.closeDate??'', body.notes??'',
          now, body.id
        ).run();
        // Audit log
        await env.DB.prepare('INSERT INTO audit_log (id, action, table_name, record_id, data, username, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime(\'now\'))').bind('audit_' + Date.now(), 'update', 'deals', body.id, JSON.stringify({company: body.company, value: body.value, stage: body.stage}), auth.user.username || '').run();
        if (body.callLog && Array.isArray(body.callLog)) {
          await env.DB.prepare('DELETE FROM call_log WHERE deal_id = ?').bind(body.id).run();
          for (const cl of body.callLog) {
            const clId = cl.id || ('cl_' + Date.now() + '_' + Math.random().toString(36).slice(2,6));
            await env.DB.prepare('INSERT INTO call_log (id, deal_id, date, time, rep, type, note) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(
              clId, body.id, cl.date||'', cl.time||'', cl.rep||'', cl.type||'Call', cl.note||'').run();
          }
        }
        return jsonResp({ success: true }, 200, request);
      }

      // ─── DELETE /api/deals/:id ─── (soft delete — moves to deleted_records for 30 days)
      const dealMatch = path.match(/^\/api\/deals\/([\w_]+)$/);
      if (dealMatch && method === 'DELETE') {
        const id = dealMatch[1];
        // Archive the deal before deleting
        const deal = await env.DB.prepare('SELECT * FROM deals WHERE id = ?').bind(id).first();
        const dealData = deal ? JSON.stringify(deal) : '{}';
        if (deal) {
          await env.DB.prepare('INSERT OR REPLACE INTO deleted_records (id, table_name, record_id, data, deleted_by, deleted_at, expires_at) VALUES (?, ?, ?, ?, ?, datetime(\'now\'), datetime(\'now\', \'30 days\'))').bind('del_' + id, 'deals', id, dealData, auth.user.username || '').run();
        }
        // Archive call logs
        const callLogs = await env.DB.prepare('SELECT * FROM call_log WHERE deal_id = ?').bind(id).all();
        for (const cl of callLogs.results) {
          await env.DB.prepare('INSERT OR REPLACE INTO deleted_records (id, table_name, record_id, data, deleted_by, deleted_at, expires_at) VALUES (?, ?, ?, ?, ?, datetime(\'now\'), datetime(\'now\', \'30 days\'))').bind('del_' + cl.id, 'call_log', cl.id, JSON.stringify(cl), auth.user.username || '').run();
        }
        await env.DB.prepare('DELETE FROM call_log WHERE deal_id = ?').bind(id).run();
        await env.DB.prepare('DELETE FROM deals WHERE id = ?').bind(id).run();
        // Audit log
        await env.DB.prepare('INSERT INTO audit_log (id, action, table_name, record_id, data, username, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime(\'now\'))').bind('audit_' + Date.now(), 'delete', 'deals', id, dealData, auth.user.username || '').run();
        return jsonResp({ success: true, message: 'Deal archived for 30 days' }, 200, request);
      }

      // ─── RESTORE /api/deals/:id/restore ───
      const restoreMatch = path.match(/^\/api\/deals\/([\w_]+)\/restore$/);
      if (restoreMatch && method === 'POST') {
        const id = restoreMatch[1];
        const archived = await env.DB.prepare('SELECT * FROM deleted_records WHERE record_id = ? AND table_name = ?').bind(id, 'deals').first();
        if (!archived) return jsonResp({ error: 'No archived deal found' }, 404, request);
        const deal = JSON.parse(archived.data);
        await env.DB.prepare(`INSERT INTO deals (id, company, contact, phone, email, value, stage, enquiryType, source, outcome, prob, brand, owner, dateContacted, followUpDate, followUpNum, dateClosed, daysToClose, nextAction, nextActionDate, closeDate, notes, createdAt, updatedAt)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
          deal.id, deal.company||'', deal.contact||'', deal.phone||'', deal.email||'',
          deal.value||0, deal.stage||'Lead', deal.enquiryType||'Website Design',
          deal.source||'Networking', deal.outcome||'Pending', deal.prob||10,
          deal.brand||'Tactik', deal.owner||'Udara',
          deal.dateContacted||'', deal.followUpDate||'', deal.followUpNum||0,
          deal.dateClosed||'', deal.daysToClose||0, deal.nextAction||'',
          deal.nextActionDate||'', deal.closeDate||'', deal.notes||'',
          deal.createdAt||'', deal.updatedAt||''
        ).run();
        // Restore call logs too
        const archivedCalls = await env.DB.prepare('SELECT * FROM deleted_records WHERE record_id LIKE ? AND table_name = ?').bind('cl_%', 'call_log').all();
        // (call logs for this deal will need separate restore if needed)
        await env.DB.prepare('DELETE FROM deleted_records WHERE record_id = ? AND table_name = ?').bind(id, 'deals').run();
        // Audit log
        await env.DB.prepare('INSERT INTO audit_log (id, action, table_name, record_id, data, username, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime(\'now\'))').bind('audit_' + Date.now(), 'restore', 'deals', id, JSON.stringify(deal), auth.user.username || '').run();
        return jsonResp({ success: true, message: 'Deal restored' }, 200, request);
      }

      // ─── GET /api/deals/deleted ─── (list soft-deleted deals, recoverable)
      if (path === '/api/deals/deleted' && method === 'GET') {
        const results = await env.DB.prepare('SELECT * FROM deleted_records WHERE table_name = ? ORDER BY deleted_at DESC').bind('deals').all();
        const deals = results.results.map(r => ({ ...r, data: JSON.parse(r.data) }));
        return jsonResp(deals, 200, request);
      }

      // ─── GET /api/audit ─── (recent audit log)
      if (path === '/api/audit' && method === 'GET') {
        const limit = parseInt(url.searchParams.get('limit') || '100');
        const results = await env.DB.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?').bind(limit).all();
        return jsonResp(results.results, 200, request);
      }

      // ─── GET /api/backup ─── (full data export for emergency restore)
      if (path === '/api/backup' && method === 'GET') {
        const deals = await env.DB.prepare('SELECT * FROM deals').all();
        const callLogs = await env.DB.prepare('SELECT * FROM call_log').all();
        const activities = await env.DB.prepare('SELECT * FROM activities').all();
        const liLeads = await env.DB.prepare('SELECT * FROM li_leads').all();
        const users = await env.DB.prepare('SELECT id, username, role, created_at FROM users').all();
        const deleted = await env.DB.prepare('SELECT * FROM deleted_records').all();
        const audit = await env.DB.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 500').all();
        return jsonResp({
          exported_at: new Date().toISOString(),
          version: '2.4',
          deals: deals.results,
          call_log: callLogs.results,
          activities: activities.results,
          li_leads: liLeads.results,
          users: users.results,
          deleted_records: deleted.results,
          audit_log: audit.results
        }, 200, request);
      }

      // ─── POST /api/restore ─── (restore from backup JSON)
      if (path === '/api/restore' && method === 'POST') {
        const body = await request.json();
        if (!body.deals || !Array.isArray(body.deals)) return jsonResp({ error: 'deals array required' }, 400, request);
        let restored = 0;
        for (const d of body.deals) {
          const existing = await env.DB.prepare('SELECT id FROM deals WHERE id = ?').bind(d.id).first();
          if (!existing) {
            await env.DB.prepare(`INSERT INTO deals (id, company, contact, phone, email, value, stage, enquiryType, source, outcome, prob, brand, owner, dateContacted, followUpDate, followUpNum, dateClosed, daysToClose, nextAction, nextActionDate, closeDate, notes, createdAt, updatedAt)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
              d.id, d.company||'', d.contact||'', d.phone||'', d.email||'',
              d.value||0, d.stage||'Lead', d.enquiryType||'Website Design',
              d.source||'Networking', d.outcome||'Pending', d.prob||10,
              d.brand||'Tactik', d.owner||'Udara',
              d.dateContacted||'', d.followUpDate||'', d.followUpNum||0,
              d.dateClosed||'', d.daysToClose||0, d.nextAction||'',
              d.nextActionDate||'', d.closeDate||'', d.notes||'',
              d.createdAt||'', d.updatedAt||''
            ).run();
            restored++;
          }
        }
        // Audit log
        await env.DB.prepare('INSERT INTO audit_log (id, action, table_name, record_id, data, username, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime(\'now\'))').bind('audit_' + Date.now(), 'restore_backup', 'deals', 'batch', JSON.stringify({restored, total: body.deals.length}), auth.user.username || '').run();
        return jsonResp({ success: true, restored, skipped: body.deals.length - restored }, 200, request);
      }

      // ─── ACTIVITIES ───
      if (path === '/api/activities' && method === 'GET') {
        const results = await env.DB.prepare('SELECT * FROM activities ORDER BY due_date DESC').all();
        return jsonResp(results.results, 200, request);
      }
      if (path === '/api/activities' && method === 'POST') {
        const body = await request.json();
        const id = body.id || ('act_' + Date.now());
        await env.DB.prepare('INSERT INTO activities (id, type, deal_id, company, rep, note, due_date, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(
          id, body.type||'Call', body.deal_id||'', body.company||'', body.rep||'Udara', body.note||'', body.due_date||'', body.status||'Pending', new Date().toISOString()).run();
        return jsonResp({ success: true, id }, 200, request);
      }
      if (path === '/api/activities' && method === 'PUT') {
        const body = await request.json();
        if (!body.id) return jsonResp({ error: 'id required' }, 400, request);
        await env.DB.prepare('UPDATE activities SET type=?, deal_id=?, company=?, rep=?, note=?, due_date=?, status=? WHERE id=?').bind(
          body.type||'Call', body.deal_id||'', body.company||'', body.rep||'Udara', body.note||'', body.due_date||'', body.status||'Pending', body.id).run();
        return jsonResp({ success: true }, 200, request);
      }
      const actMatch = path.match(/^\/api\/activities\/([\w_]+)$/);
      if (actMatch && method === 'DELETE') {
        await env.DB.prepare('DELETE FROM activities WHERE id = ?').bind(actMatch[1]).run();
        return jsonResp({ success: true }, 200, request);
      }

      // ─── POST /api/activities/bulk ───
      if (path === '/api/activities/bulk' && method === 'POST') {
        const body = await request.json();
        if (!Array.isArray(body.activities)) return jsonResp({ error: 'activities array required' }, 400, request);
        // SAFETY: No prune on activities bulk sync — only upsert.
        let inserted = 0;
        for (const a of body.activities) {
          const id = a.id || ('act_' + Date.now() + '_' + Math.random().toString(36).slice(2,6));
          await env.DB.prepare('INSERT OR REPLACE INTO activities (id, type, deal_id, company, rep, note, due_date, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(
            id, a.type||'Call', a.deal_id||'', a.company||'', a.rep||'Udara', a.note||'', a.due_date||'', a.status||'Pending', a.created_at||new Date().toISOString()).run();
          inserted++;
        }
        return jsonResp({ success: true, inserted }, 200, request);
      }

      // ─── COLD CALLS (li-leads) ───
      // Auto-migrate: add new columns if missing
      try {
        const cols = await env.DB.prepare("PRAGMA table_info(li_leads)").all();
        const colNames = cols.results.map(c => c.name);
        if (!colNames.includes('firstName')) await env.DB.prepare('ALTER TABLE li_leads ADD COLUMN firstName TEXT DEFAULT \'\'').run();
        if (!colNames.includes('lastName')) await env.DB.prepare('ALTER TABLE li_leads ADD COLUMN lastName TEXT DEFAULT \'\'').run();
        if (!colNames.includes('mobile')) await env.DB.prepare('ALTER TABLE li_leads ADD COLUMN mobile TEXT DEFAULT \'\'').run();
        if (!colNames.includes('email')) await env.DB.prepare('ALTER TABLE li_leads ADD COLUMN email TEXT DEFAULT \'\'').run();
        if (!colNames.includes('website')) await env.DB.prepare('ALTER TABLE li_leads ADD COLUMN website TEXT DEFAULT \'\'').run();
      } catch (migrateErr) { /* ignore if columns already exist */ }

      if (path === '/api/li-leads' && method === 'GET') {
        const results = await env.DB.prepare('SELECT * FROM li_leads ORDER BY date DESC').all();
        return jsonResp(results.results, 200, request);
      }
      if (path === '/api/li-leads' && method === 'POST') {
        const body = await request.json();
        const id = body.id || ('li_' + Date.now());
        await env.DB.prepare('INSERT INTO li_leads (id, name, company, title, status, message, date, rep, notes, created_at, firstName, lastName, mobile, email, website) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(
          id, body.name||'', body.company||'', body.title||'', body.status||'New', body.message||'', body.date||'', body.rep||'VA', body.notes||'', new Date().toISOString(), body.firstName||'', body.lastName||'', body.mobile||'', body.email||'', body.website||'').run();
        return jsonResp({ success: true, id }, 200, request);
      }
      // ─── POST /api/li-leads/bulk ───
      if (path === '/api/li-leads/bulk' && method === 'POST') {
        const body = await request.json();
        if (!Array.isArray(body.leads)) return jsonResp({ error: 'leads array required' }, 400, request);
        // SAFETY: No prune on li_leads bulk sync — only upsert.
        let inserted = 0;
        for (const l of body.leads) {
          const id = l.id || ('li_' + Date.now() + '_' + Math.random().toString(36).slice(2,6));
          await env.DB.prepare('INSERT OR REPLACE INTO li_leads (id, name, company, title, status, message, date, rep, notes, created_at, firstName, lastName, mobile, email, website) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(
            id, l.name||'', l.company||'', l.title||'', l.status||'New', l.message||'', l.date||'', l.rep||'VA', l.notes||'', l.created_at||new Date().toISOString(), l.firstName||'', l.lastName||'', l.mobile||'', l.email||'', l.website||'').run();
          inserted++;
        }
        return jsonResp({ success: true, inserted }, 200, request);
      }

      if (path === '/api/li-leads' && method === 'PUT') {
        const body = await request.json();
        if (!body.id) return jsonResp({ error: 'id required' }, 400, request);
        await env.DB.prepare('UPDATE li_leads SET name=?, company=?, title=?, status=?, message=?, date=?, rep=?, notes=?, firstName=?, lastName=?, mobile=?, email=?, website=? WHERE id=?').bind(
          body.name||'', body.company||'', body.title||'', body.status||'New', body.message||'', body.date||'', body.rep||'VA', body.notes||'', body.firstName||'', body.lastName||'', body.mobile||'', body.email||'', body.website||'', body.id).run();
        return jsonResp({ success: true }, 200, request);
      }
      const liMatch = path.match(/^\/api\/li-leads\/([\w_]+)$/);
      if (liMatch && method === 'DELETE') {
        await env.DB.prepare('DELETE FROM li_leads WHERE id = ?').bind(liMatch[1]).run();
        return jsonResp({ success: true }, 200, request);
      }

      // ─── USERS (admin only) ───
      if (path === '/api/users' && method === 'GET' && auth.user.role === 'admin') {
        const results = await env.DB.prepare('SELECT id, username, role, created_at FROM users').all();
        return jsonResp(results.results, 200, request);
      }
      if (path === '/api/users' && method === 'POST' && auth.user.role === 'admin') {
        const body = await request.json();
        if (!body.username || !body.password) return jsonResp({ error: 'Username and password required' }, 400, request);
        const hash = await hashPassword(body.password);
        const id = 'u_' + Date.now();
        try {
          await env.DB.prepare('INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)').bind(id, body.username, hash, body.role || 'user', new Date().toISOString()).run();
          return jsonResp({ success: true, id }, 200, request);
        } catch (e) {
          return jsonResp({ error: 'Username already exists' }, 400, request);
        }
      }

      return jsonResp({ error: 'Not found' }, 404, request);
    }

    // For all non-API routes, pass through to Pages (serve static files)
    return context.next();
  } catch (err) {
    return jsonResp({ error: 'Internal server error', details: err.message }, 500, request);
  }
}
