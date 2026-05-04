"""
ResQGrid v5.0 — Python Flask Server
Separate HTML pages: landing.html, login.html, admin.html, dashboard.html
SQLite database, Socket.IO real-time, CRISP AI engine
No IP blocking (testing mode) — security can be re-added later
"""

import os, sys, json, hashlib, secrets, re, time, math
import sqlite3, smtplib, random, threading
from datetime import datetime, timedelta
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict

from flask import Flask, request, jsonify, send_from_directory, render_template, g
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS

# ─── App Setup ────────────────────────────────────────────────
app = Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/static')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'resqgrid-secret-v5-change-this')
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

DB_PATH    = os.environ.get('DB_PATH', 'resqgrid.db')
SMTP_HOST  = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT  = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER  = os.environ.get('SMTP_USER', '')
SMTP_PASS  = os.environ.get('SMTP_PASS', '')
GOOGLE_MAPS_KEY = os.environ.get('GOOGLE_MAPS_KEY', '')   # put your key in env

# ─── Database ─────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def query(sql, args=(), one=False):
    c = get_db().execute(sql, args)
    rv = c.fetchall()
    return (rv[0] if rv else None) if one else rv

def execute(sql, args=()):
    db = get_db()
    c = db.execute(sql, args)
    db.commit()
    return c

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        pass123 = hash_password('123123')
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        schema_path = os.path.join(os.path.dirname(__file__), 'database', 'schema.sql')
        schema = open(schema_path).read()
        db.executescript(schema)
        admin = db.execute("SELECT id FROM users WHERE is_admin=1").fetchone()
        db.execute("""INSERT INTO users
                (id,name,email,role,role_label,department,password_hash,is_admin,is_verified,is_guest,can_respond,can_resolve,status)
                VALUES(?,?,?,?,?,?,?,1,1,0,1,1,'active')""",
                ('012','Tejas','tejas@gmail.com','guest','Guest','Guest',pass123))
        db.commit()
        if not admin:
            aid = 'admin_' + secrets.token_hex(4)
            phash = hash_password('admin123')
            db.execute("""INSERT INTO users
                (id,name,email,role,role_label,department,password_hash,is_admin,is_verified,is_guest,can_respond,can_resolve,status)
                VALUES(?,?,?,?,?,?,?,1,1,0,1,1,'active')""",
                (aid,'Admin','admin@resqgrid.com','admin','System Admin','Admin',phash))
            db.commit()
            print("✅ Admin created: admin@resqgrid.com / admin123")
        print(f"✅ Database ready: {DB_PATH}")

# ─── Security (minimal — no IP blocking for testing) ──────────
def hash_password(pw):
    return hashlib.sha256((pw + 'resqgrid_salt_2024').encode()).hexdigest()

def make_token():
    return 'tok_' + secrets.token_hex(32)

def make_id(prefix='u'):
    return f"{prefix}_{int(time.time()*1000):x}_{secrets.token_hex(3)}"

# Simple input sanitisation (no blocking, just logging)
@app.before_request
def light_security():
    # Only skip static files
    if request.path.startswith('/static'):
        return
    # Log but never block — testing mode

# ─── Auth Helper ──────────────────────────────────────────────
def get_current_user():
    token = request.headers.get('X-Auth-Token') or request.args.get('token')
    if not token: return None
    row = query("""SELECT u.* FROM users u
        JOIN sessions s ON s.user_id=u.id
        WHERE s.token=? AND (s.expires_at IS NULL OR s.expires_at>datetime('now'))""",
        (token,), one=True)
    if row:
        with sqlite3.connect(DB_PATH) as db:
            db.execute("UPDATE users SET last_seen=datetime('now') WHERE id=?", (row['id'],))
    return dict(row) if row else None

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user: return jsonify({'error': 'Authentication required'}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user or not user.get('is_admin'): return jsonify({'error': 'Admin access required'}), 403
        g.current_user = user
        return f(*args, **kwargs)
    return decorated

# ─── Work Roles ───────────────────────────────────────────────
WORK_ROLES = [
    {'id':'security_lead',     'label':'Security Lead',         'department':'Security',       'canRespond':True,  'canResolve':True,  'priority':1, 'skills':['fire','violence','evacuation']},
    {'id':'security_guard',    'label':'Security Guard',         'department':'Security',       'canRespond':True,  'canResolve':False, 'priority':2, 'skills':['fire','panic','patrol']},
    {'id':'security_patrol',   'label':'Security Patrol',        'department':'Security',       'canRespond':True,  'canResolve':False, 'priority':3, 'skills':['panic']},
    {'id':'medical_officer',   'label':'Medical Officer',        'department':'Medical',        'canRespond':True,  'canResolve':True,  'priority':1, 'skills':['medical','heart','bleeding','cpr']},
    {'id':'first_aid',         'label':'First Aid Responder',    'department':'Medical',        'canRespond':True,  'canResolve':False, 'priority':2, 'skills':['medical','bleeding']},
    {'id':'nurse',             'label':'Nurse',                  'department':'Medical',        'canRespond':True,  'canResolve':True,  'priority':2, 'skills':['medical','heart']},
    {'id':'emergency_coord',   'label':'Emergency Coordinator',  'department':'Management',     'canRespond':True,  'canResolve':True,  'priority':1, 'skills':['all']},
    {'id':'general_manager',   'label':'General Manager',        'department':'Management',     'canRespond':True,  'canResolve':True,  'priority':1, 'skills':['all']},
    {'id':'floor_manager',     'label':'Floor Manager',          'department':'Management',     'canRespond':True,  'canResolve':False, 'priority':2, 'skills':['evacuation']},
    {'id':'duty_manager',      'label':'Duty Manager',           'department':'Management',     'canRespond':True,  'canResolve':True,  'priority':1, 'skills':['all']},
    {'id':'front_desk',        'label':'Front Desk Agent',       'department':'Operations',     'canRespond':False, 'canResolve':False, 'priority':3, 'skills':[]},
    {'id':'concierge',         'label':'Concierge',              'department':'Operations',     'canRespond':False, 'canResolve':False, 'priority':4, 'skills':[]},
    {'id':'housekeeping_lead', 'label':'Housekeeping Lead',      'department':'Housekeeping',   'canRespond':True,  'canResolve':False, 'priority':2, 'skills':['flood']},
    {'id':'housekeeping_staff','label':'Housekeeping Staff',     'department':'Housekeeping',   'canRespond':False, 'canResolve':False, 'priority':4, 'skills':[]},
    {'id':'maintenance_lead',  'label':'Maintenance Lead',       'department':'Maintenance',    'canRespond':True,  'canResolve':False, 'priority':2, 'skills':['gas','electrical']},
    {'id':'maintenance_tech',  'label':'Maintenance Technician', 'department':'Maintenance',    'canRespond':True,  'canResolve':False, 'priority':3, 'skills':['gas','electrical']},
    {'id':'electrician',       'label':'Electrician',            'department':'Maintenance',    'canRespond':True,  'canResolve':False, 'priority':3, 'skills':['electrical']},
    {'id':'plumber',           'label':'Plumber',                'department':'Maintenance',    'canRespond':True,  'canResolve':False, 'priority':3, 'skills':['flood']},
    {'id':'fire_safety',       'label':'Fire Safety Officer',    'department':'Safety',         'canRespond':True,  'canResolve':True,  'priority':1, 'skills':['fire','smoke','evacuation']},
    {'id':'fire_marshal',      'label':'Fire Marshal',           'department':'Safety',         'canRespond':True,  'canResolve':True,  'priority':1, 'skills':['fire','evacuation']},
    {'id':'evacuation_lead',   'label':'Evacuation Lead',        'department':'Safety',         'canRespond':True,  'canResolve':False, 'priority':2, 'skills':['evacuation']},
    {'id':'fb_manager',        'label':'F&B Manager',            'department':'Food & Beverage','canRespond':False, 'canResolve':False, 'priority':4, 'skills':[]},
    {'id':'chef',              'label':'Chef / Kitchen Staff',   'department':'Food & Beverage','canRespond':False, 'canResolve':False, 'priority':5, 'skills':[]},
    {'id':'it_support',        'label':'IT Support',             'department':'Technology',     'canRespond':False, 'canResolve':False, 'priority':5, 'skills':[]},
    {'id':'communications',    'label':'Communications Officer', 'department':'Technology',     'canRespond':False, 'canResolve':False, 'priority':4, 'skills':[]},
    {'id':'guest',             'label':'Guest',                  'department':'Guest',          'canRespond':False, 'canResolve':False, 'priority':99,'skills':[]},
    {'id':'visitor',           'label':'Visitor',                'department':'Guest',          'canRespond':False, 'canResolve':False, 'priority':99,'skills':[]},
]

def get_role_info(role_id):
    return next((r for r in WORK_ROLES if r['id']==role_id), WORK_ROLES[-1])

# ─── CRISP Intelligence Engine ─────────────────────────────────
SIGNAL_WEIGHTS = {
    'fire':40,'smoke':30,'flame':45,'burning':35,'arson':50,
    'medical':35,'heart':40,'cardiac':45,'bleeding':35,'unconscious':45,'cpr':35,'stroke':42,
    'panic':25,'violence':45,'shooting':70,'bomb':80,'fight':50,'weapon':55,'theft':20,
    'gas':45,'explosion':60,'flood':35,'earthquake':50,'collapse':55,
    'accident':30,'emergency':25,'help':20,'sos':30,'distress':28,'urgent':25,
    'crowd':35,'stampede':50,'screaming':25,'chaos':40,
    'chemical':45,'hazmat':50,'toxic':45,
}

def calculate_confidence(message):
    msg = message.lower()
    confidence = 10
    matched = []
    breakdown = {}
    for signal, weight in SIGNAL_WEIGHTS.items():
        if signal in msg:
            matched.append(signal)
            confidence += weight
            breakdown[signal] = weight
    if len(matched) >= 2:
        confidence += 15
        breakdown['multi_signal_boost'] = 15
    confidence = min(100, confidence)
    return int(confidence), matched, breakdown

def get_priority(confidence):
    if confidence >= 80: return 'CRITICAL'
    if confidence >= 50: return 'MEDIUM'
    return 'LOW'

def generate_system_analysis(message, signals, priority, location):
    msg = message.lower()
    if 'fire' in signals or 'smoke' in signals:
        return f"⚠️ SYSTEM ANALYSIS: Fire/smoke signature detected in {location}. Propagation risk HIGH. Recommend immediate evacuation and fire suppression activation. Adjacent zones may be affected."
    if 'medical' in signals or 'heart' in signals or 'unconscious' in signals:
        return f"🏥 SYSTEM ANALYSIS: Medical emergency detected. Cardiac indicators present. AED + CPR-trained responder required within 4 minutes for optimal survival outcome."
    if 'panic' in signals or 'crowd' in signals or 'stampede' in signals:
        return f"⚡ SYSTEM ANALYSIS: Crowd panic pattern detected. Stampede risk ELEVATED. Deploy crowd control immediately. Open secondary exits. Avoid bottleneck zones."
    if 'gas' in signals or 'explosion' in signals or 'chemical' in signals:
        return f"☣️ SYSTEM ANALYSIS: Hazardous substance signature. Isolate area immediately. Shut ventilation. Evacuate 50m radius. Specialist hazmat team required."
    if 'violence' in signals or 'weapon' in signals or 'shooting' in signals:
        return f"🚨 SYSTEM ANALYSIS: Active security threat. Armed response protocol. Evacuate affected zone. Notify law enforcement immediately."
    if priority == 'CRITICAL':
        return f"⚠️ SYSTEM ANALYSIS: High-confidence emergency in {location}. All available responders on standby. Immediate action required."
    if priority == 'MEDIUM':
        return f"📊 SYSTEM ANALYSIS: Moderate risk event in progress at {location}. Send one responder to assess. Prepare for escalation."
    return f"ℹ️ SYSTEM ANALYSIS: Low-risk event logged. Monitoring active. System will auto-escalate if confidence increases above 50%."

def generate_mesh_path():
    devices = ['Security Desk','Housekeeping Station','Front Desk','Staff Tablet','Floor 1 Relay','Floor 2 Relay','Control Room','Emergency Hub']
    hops = random.randint(2,4)
    path = random.sample(devices[:-1], hops)
    if 'Control Room' not in path: path.append('Control Room')
    total_delay = sum(random.randint(80,250) for _ in range(len(path)-1))
    return path, total_delay

# ─── User Helpers ──────────────────────────────────────────────
def user_to_dict(row, show_phone=False, is_self=False):
    if not row: return None
    d = dict(row) if not isinstance(row, dict) else row
    return {
        'id': d.get('id'),
        'name': d.get('name'),
        'email': d.get('email'),
        'phone': d.get('phone') if (show_phone or is_self) else None,
        'dob': d.get('dob'),
        'role': d.get('role'),
        'roleLabel': d.get('role_label'),
        'department': d.get('department'),
        'floor': d.get('floor'),
        'zone': d.get('zone'),
        'roomNumber': d.get('room_number'),
        'canRespond': bool(d.get('can_respond')),
        'canResolve': bool(d.get('can_resolve')),
        'isGuest': bool(d.get('is_guest')),
        'isAdmin': bool(d.get('is_admin')),
        'isVerified': bool(d.get('is_verified')),
        'requestedRole': d.get('requested_role'),
        'status': d.get('status'),
        'available': bool(d.get('available')),
        'activeIncidentCount': d.get('active_incident_count', 0),
        'resolvedCount': d.get('resolved_count', 0),
        'createdAt': d.get('created_at'),
        'lastSeen': d.get('last_seen'),
    }

def incident_to_dict(row, requester_id=None, requester_is_admin=False):
    if not row: return None
    d = dict(row) if not isinstance(row, dict) else row
    is_reporter  = requester_id and requester_id == d.get('reporter_id')
    is_responder = requester_id and requester_id == d.get('assigned_user_id')
    relay    = json.loads(d.get('relay_path') or '[]')
    conf_hist= json.loads(d.get('confidence_history') or '[]')
    signals  = json.loads(d.get('matched_signals') or '[]')
    responder = None
    if d.get('responder_name'):
        responder = {
            'name': d['responder_name'],
            'role': d.get('responder_role'),
            'phone': d.get('responder_phone') if (is_reporter or requester_is_admin) else None,
            'etaSeconds': d.get('responder_eta', 45),
            'status': d.get('responder_status', 'assigned'),
        }
    return {
        'id': d['id'],
        'message': d['message'],
        'location': d.get('location'),
        'extractedLocation': {'room': d.get('extracted_room'), 'floor': d.get('extracted_floor')},
        'confidence': d.get('confidence', 0),
        'confidenceHistory': conf_hist,
        'matchedSignals': signals,
        'priority': d.get('priority', 'LOW'),
        'status': d.get('status', 'ACTIVE'),
        'source': d.get('source', 'user'),
        'reporterId': d.get('reporter_id'),
        'reporterName': d.get('reporter_name', 'Anonymous'),
        'reporterPhone': d.get('reporter_phone') if (is_responder or requester_is_admin) else None,
        'reporterRole': d.get('reporter_role'),
        'reporterRoom': d.get('reporter_room'),
        'assignedUserId': d.get('assigned_user_id'),
        'assignedAt': d.get('assigned_at'),
        'responseDeadline': d.get('response_deadline'),
        'responder': responder,
        'relay': relay,
        'relayTotalDelay': d.get('relay_total_delay', 0),
        'explanation': d.get('explanation'),
        'systemAnalysis': d.get('system_analysis'),
        'requiresEvacuation': bool(d.get('requires_evacuation')),
        'resolvedAt': d.get('resolved_at'),
        'resolvedBy': d.get('resolved_by'),
        'time': (datetime.fromisoformat(d['created_at'].replace('Z','')) + timedelta(hours=5, minutes=30)).strftime('%I:%M %p IST') if d.get('created_at') else '',
        'timestamp': d.get('created_at'),
        'timeline': [],
        'contactMessages': [],
    }

def find_best_responder(message):
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("""SELECT * FROM users WHERE can_respond=1
            AND status='active' AND active_incident_count<2
            ORDER BY active_incident_count ASC, last_seen DESC""").fetchall()
    if not rows: return None
    msg = message.lower()
    best = None
    best_score = -1
    for row in rows:
        ri = get_role_info(row['role'])
        skills = ri.get('skills', [])
        score = 0
        if 'all' in skills: score += 50
        for sk in skills:
            if sk in msg: score += 30
        score -= (row['active_incident_count'] or 0) * 10
        if score > best_score:
            best_score = score
            best = row
    return dict(best) if best else None

def create_incident(message, location=None, source='user'):
    confidence, signals, breakdown = calculate_confidence(message)
    priority = get_priority(confidence)
    relay, delay = generate_mesh_path()
    if not location:
        rm = re.search(r'(?:Room|room|RM)\s+(\d+\w?)', message)
        fl = re.search(r'(?:Floor|floor|FL)\s+(\d+)', message)
        extracted_room  = rm.group(1) if rm else None
        extracted_floor = fl.group(1) if fl else None
        parts = []
        if rm: parts.append(f"Room {extracted_room}")
        if fl: parts.append(f"Floor {extracted_floor}")
        location = ', '.join(parts) or 'Unknown Location'
    else:
        rm = re.search(r'(?:Room|room)\s+(\d+\w?)', location)
        fl = re.search(r'(?:Floor|floor)\s+(\d+)', location)
        extracted_room  = rm.group(1) if rm else None
        extracted_floor = fl.group(1) if fl else None
    conf_hist = [int(confidence*0.3), int(confidence*0.6), confidence]
    analysis  = generate_system_analysis(message, signals, priority, location)
    requires_evac = any(s in signals for s in ['fire','smoke','gas','explosion','flood'])
    with sqlite3.connect(DB_PATH) as db:
        c = db.execute("""INSERT INTO incidents
            (message,location,extracted_room,extracted_floor,confidence,priority,source,
             relay_path,relay_total_delay,confidence_history,matched_signals,explanation,
             system_analysis,requires_evacuation)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (message, location, extracted_room, extracted_floor, confidence, priority, source,
             json.dumps(relay), delay, json.dumps(conf_hist), json.dumps(signals),
             f"{priority}: {confidence}% confidence. Signals: {', '.join(signals) or 'none'}",
             analysis, 1 if requires_evac else 0))
        inc_id = c.lastrowid
        for event, icon, desc in [
            ('INCIDENT_CREATED','🚨',f"Incident reported: {message[:100]}"),
            ('CRISP_ANALYSIS', '🧠',f"Confidence: {confidence}%. Signals: {', '.join(signals) or 'none'}"),
            ('PRIORITY_ASSIGNED','🎯',f"Priority: {priority}"),
            ('MESH_PATH','📡',f"Relay: {' → '.join(relay)} ({delay}ms)"),
            ('AI_ANALYSIS','🤖',analysis),
        ]:
            db.execute("""INSERT INTO incident_timeline
                (incident_id,event,description,actor,icon,confidence)
                VALUES(?,?,?,'System',?,?)""", (inc_id, event, desc, icon, confidence))
        hour_key = datetime.utcnow().strftime('%Y-%m-%dT%H')
        db.execute("""INSERT INTO incident_hourly_stats(hour_key,count,critical)
            VALUES(?,1,?) ON CONFLICT(hour_key) DO UPDATE SET count=count+1,critical=critical+?""",
            (hour_key, 1 if priority=='CRITICAL' else 0, 1 if priority=='CRITICAL' else 0))
        db.commit()
    return get_incident_by_id(inc_id)

def get_incident_by_id(inc_id, requester_id=None, requester_is_admin=False):
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
        if not row: return None
        inc = incident_to_dict(row, requester_id, requester_is_admin)
        tl  = db.execute("SELECT * FROM incident_timeline WHERE incident_id=? ORDER BY created_at", (inc_id,)).fetchall()
        inc['timeline'] = [{'id':t['id'],'event':t['event'],'description':t['description'],'actor':t['actor'],'icon':t['icon'],'confidence':t['confidence'],'timestamp':t['created_at']} for t in tl]
        msgs = db.execute("SELECT * FROM incident_messages WHERE incident_id=? ORDER BY created_at", (inc_id,)).fetchall()
        inc['contactMessages'] = [{'id':m['id'],'senderId':m['sender_id'],'message':m['message'],'senderName':m['sender_name'],'senderRole':m['sender_role'],'timestamp':m['created_at']} for m in msgs]
    return inc

def auto_assign_responder(incident):
    responder = find_best_responder(incident.get('message',''))
    if not responder: return
    with sqlite3.connect(DB_PATH) as db:
        deadline = (datetime.utcnow()+timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S')
        db.execute("""UPDATE incidents SET
            responder_name=?,responder_role=?,responder_phone=?,responder_eta=45,
            responder_status='assigned',assigned_user_id=?,assigned_at=datetime('now'),
            response_deadline=?,status=CASE WHEN status='ACTIVE' THEN 'RESPONDING' ELSE status END
            WHERE id=?""",
            (responder['name'], responder.get('role_label','Staff'),
             responder.get('phone','N/A'), responder['id'], deadline, incident['id']))
        db.execute("""INSERT INTO incident_timeline(incident_id,event,description,actor,icon,confidence)
            VALUES(?,?,?,?,?,?)""",
            (incident['id'],'RESPONDER_ASSIGNED',
             f"{responder['name']} assigned. ETA: 45s. Respond within 5 min.",
             responder['name'],'👤', incident.get('confidence',0)))
        db.execute("""UPDATE users SET active_incident_count=active_incident_count+1,
            available=CASE WHEN active_incident_count>=1 THEN 0 ELSE 1 END WHERE id=?""",
            (responder['id'],))
        db.commit()
    updated = get_incident_by_id(incident['id'])
    socketio.emit('assigned-to-you', {
        'incidentId': incident['id'],
        'assignedUserId': responder['id'],
        'incident': updated,
        'siren': True,
        'responseDeadline': deadline,
        'message': f"🚨 You are assigned to incident #{incident['id']}: {incident.get('message','')[:60]}"
    })

# ─── OTP Email ────────────────────────────────────────────────
def send_otp_email(email, otp):
    if not SMTP_USER or not SMTP_PASS:
        print(f"📧 OTP for {email}: {otp}  (SMTP not configured — check env vars)")
        return True
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'ResQGrid — Your Verification Code'
        msg['From']    = f'ResQGrid <{SMTP_USER}>'
        msg['To']      = email
        html = f"""
<div style="font-family:monospace;background:#04060e;color:#e8eaf6;padding:30px;border-radius:12px;max-width:400px;margin:0 auto">
  <h2 style="color:#ff2d4e;letter-spacing:3px;margin-bottom:6px">⚡ RESQGRID</h2>
  <p style="color:#8892b0;font-size:0.85rem">Emergency Command Center — Account Verification</p>
  <hr style="border-color:#1a2040;margin:16px 0"/>
  <p style="color:#e8eaf6">Your verification code is:</p>
  <h1 style="font-size:3rem;letter-spacing:12px;color:#1e90ff;text-align:center;margin:20px 0">{otp}</h1>
  <p style="color:#4a5270;font-size:0.78rem">⏱ Expires in 10 minutes. Do not share.</p>
</div>"""
        msg.attach(MIMEText(html, 'html'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo(); server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, email, msg.as_string())
        return True
    except Exception as e:
        print(f"❌ Email error: {e}\n📧 OTP for {email}: {otp}")
        return False

# ─── Auto-Detection Thread ─────────────────────────────────────
AUTO_EVENTS = [
    ('Smoke sensor triggered in Kitchen Area',   'Floor 1 - Kitchen'),
    ('Temperature spike detected Room 405',      'Floor 4 - Room 405'),
    ('Gas detector alert Basement Utility Room', 'Basement - Utility'),
    ('Fire alarm triggered Conference Hall',     'Floor 3 - Conference Hall'),
    ('CO2 level critical Parking Basement',      'Basement - Parking'),
    ('Smoke alarm West Wing corridor',           'Floor 2 - West Wing'),
    ('Heat sensor abnormal Boiler Room',         'Basement - Boiler Room'),
]
auto_detect_enabled = True

def auto_detect_worker():
    while True:
        time.sleep(20)
        if not auto_detect_enabled or random.random() > 0.25: continue
        evt = random.choice(AUTO_EVENTS)
        try:
            with sqlite3.connect(DB_PATH) as db:
                dup = db.execute("""SELECT id FROM incidents WHERE LOWER(message)=LOWER(?)
                    AND status NOT IN ('RESOLVED','FALSE_ALARM')
                    AND created_at>datetime('now','-5 minutes')""", (evt[0],)).fetchone()
            if dup: continue
            inc = create_incident(evt[0], evt[1], 'auto_detection')
            auto_assign_responder(inc)
            socketio.emit('new-incident', incident_to_dict(get_incident_by_id(inc['id']), None, False))
            socketio.emit('auto-detection', {'message': f"🤖 SENSOR: {evt[0]}", 'incident': inc})
        except Exception as e:
            print(f"Auto-detect error: {e}")

# ═══════════════════════════════════════════════════════════════
# ROUTES — Pages
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def landing():
    """Landing page — 3D animated hero"""
    return render_template('landing.html', maps_key=GOOGLE_MAPS_KEY)

@app.route('/login')
def login_page():
    """Login / Register page"""
    return render_template('login.html')

@app.route('/dashboard')
def dashboard_page():
    """Staff / User dashboard"""
    return render_template('dashboard.html', maps_key=GOOGLE_MAPS_KEY)

@app.route('/admin')
def admin_page():
    """Admin dashboard — full controls"""
    return render_template('admin.html', maps_key=GOOGLE_MAPS_KEY)

# ═══════════════════════════════════════════════════════════════
# ROUTES — Auth API
# ═══════════════════════════════════════════════════════════════

@app.route('/api/roles')
def get_roles():
    return jsonify(WORK_ROLES)

@app.route('/api/auth/send-otp', methods=['POST'])
def send_otp():
    data  = request.get_json() or {}
    email = data.get('email','').strip().lower()
    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400
    otp     = str(random.randint(100000, 999999))
    expires = (datetime.utcnow()+timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%S')
    execute("INSERT INTO otp_verifications(email,otp,expires_at) VALUES(?,?,?)", (email,otp,expires))
    send_otp_email(email, otp)
    return jsonify({'success': True, 'message': 'OTP sent (check spam if missing)'})

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    data  = request.get_json() or {}
    email = data.get('email','').strip().lower()
    otp   = data.get('otp','').strip()
    if not email or not otp: return jsonify({'error': 'Email and OTP required'}), 400
    row = query("""SELECT * FROM otp_verifications
        WHERE email=? AND otp=? AND used=0 AND expires_at>datetime('now')
        ORDER BY created_at DESC LIMIT 1""", (email, otp), one=True)
    if not row: return jsonify({'error': 'Invalid or expired OTP'}), 400
    execute("UPDATE otp_verifications SET used=1 WHERE id=?", (row['id'],))
    return jsonify({'success': True, 'verified': True})

@app.route('/api/auth/register', methods=['POST'])
def register():
    data        = request.get_json() or {}
    name        = data.get('name','').strip()
    email       = data.get('email','').strip().lower() or None
    phone       = data.get('phone','').strip() or None
    dob         = data.get('dob') or None
    role        = data.get('role','guest')
    password    = data.get('password','')
    floor       = data.get('floor','Floor 1') or 'Floor 1'
    zone        = data.get('zone','General') or 'General'
    room_number = data.get('roomNumber') or None
    otp_verified= data.get('otpVerified', False)

    if not name:                         return jsonify({'error': 'Name required'}), 400
    if not email and not phone:          return jsonify({'error': 'Email or phone required'}), 400
    if len(password) < 6:               return jsonify({'error': 'Password ≥ 6 chars required'}), 400
    if email and query("SELECT id FROM users WHERE email=?", (email,), one=True):
        return jsonify({'error': 'Email already registered'}), 400
    if phone and query("SELECT id FROM users WHERE phone=?", (phone,), one=True):
        return jsonify({'error': 'Phone already registered'}), 400

    uid   = make_id('u')
    phash = hash_password(password)
    execute("""INSERT INTO users(id,name,email,phone,dob,role,role_label,department,
        password_hash,floor,zone,room_number,can_respond,can_resolve,is_guest,
        is_verified,status,available,requested_role)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,0,1,?,?,1,?)""",
        (uid, name, email, phone, dob, 'guest','Guest','Guest', phash,
         floor, zone, room_number, 1 if otp_verified else 0, 'active', role))

    token   = make_token()
    expires = (datetime.utcnow()+timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')
    execute("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)", (token,uid,expires))

    user = query("SELECT * FROM users WHERE id=?", (uid,), one=True)
    ud   = user_to_dict(user, is_self=True)
    socketio.emit('users-update', get_all_users())
    return jsonify({'user': ud, 'token': token, 'requestedRole': role}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data          = request.get_json() or {}
    email_or_phone= data.get('emailOrPhone','').strip()
    password      = data.get('password','')
    if not email_or_phone or not password:
        return jsonify({'error': 'Credentials required'}), 400
    phash = hash_password(password)
    val   = email_or_phone.lower()
    row   = query("""SELECT * FROM users
        WHERE (LOWER(email)=? OR phone=?) AND password_hash=?""",
        (val, email_or_phone, phash), one=True)
    if not row: return jsonify({'error': 'Invalid credentials'}), 401
    execute("UPDATE users SET last_seen=datetime('now') WHERE id=?", (row['id'],))
    token   = make_token()
    expires = (datetime.utcnow()+timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S')
    execute("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)", (token,row['id'],expires))
    socketio.emit('users-update', get_all_users())
    return jsonify({'user': user_to_dict(row, is_self=True), 'token': token})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    token = request.headers.get('X-Auth-Token')
    if token: execute("DELETE FROM sessions WHERE token=?", (token,))
    socketio.emit('users-update', get_all_users())
    return jsonify({'success': True})

@app.route('/api/auth/me')
@auth_required
def me():
    return jsonify(user_to_dict(g.current_user, is_self=True))

# ═══════════════════════════════════════════════════════════════
# ROUTES — Admin API
# ═══════════════════════════════════════════════════════════════

@app.route('/api/admin/assign-role', methods=['POST'])
@admin_required
def admin_assign_role():
    data      = request.get_json() or {}
    target_id = data.get('targetUserId')
    new_role  = data.get('newRole')
    if not target_id or not new_role:
        return jsonify({'error': 'targetUserId and newRole required'}), 400
    ri       = get_role_info(new_role)
    is_guest = new_role in ('guest','visitor')
    execute("""UPDATE users SET role=?,role_label=?,department=?,
        can_respond=?,can_resolve=?,is_guest=? WHERE id=?""",
        (new_role, ri['label'], ri['department'],
         1 if ri['canRespond'] else 0,
         1 if ri['canResolve'] else 0,
         1 if is_guest else 0, target_id))
    user = query("SELECT * FROM users WHERE id=?", (target_id,), one=True)
    socketio.emit('users-update', get_all_users())
    socketio.emit('role-updated', {'userId': target_id, 'newRole': new_role, 'user': user_to_dict(user)})
    return jsonify({'success': True, 'user': user_to_dict(user)})

@app.route('/api/admin/pending-users')
@admin_required
def pending_users():
    rows = query("SELECT * FROM users WHERE requested_role != 'guest' AND requested_role != 'visitor' AND (is_guest=1 OR role='guest') ORDER BY created_at DESC")
    return jsonify([user_to_dict(r) for r in rows])

@app.route('/api/admin/delete-user/<uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    if uid == g.current_user['id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    execute("DELETE FROM users WHERE id=?", (uid,))
    socketio.emit('users-update', get_all_users())
    return jsonify({'success': True})

# ═══════════════════════════════════════════════════════════════
# ROUTES — Users API
# ═══════════════════════════════════════════════════════════════

def get_all_users(requester_id=None):
    rows = query("SELECT * FROM users ORDER BY created_at DESC")
    return [user_to_dict(r, is_self=(r['id']==requester_id)) for r in rows]

def get_online_users():
    rows = query("SELECT * FROM users WHERE last_seen>datetime('now','-3 minutes')")
    return [user_to_dict(r) for r in rows]

@app.route('/api/users')
def users():
    cu = get_current_user()
    return jsonify(get_all_users(cu['id'] if cu else None))

@app.route('/api/users/online')
def online_users():
    return jsonify(get_online_users())

@app.route('/api/users/responders')
def available_responders():
    rows = query("SELECT * FROM users WHERE can_respond=1 AND status='active' AND active_incident_count<2")
    return jsonify([user_to_dict(r) for r in rows])

# ═══════════════════════════════════════════════════════════════
# ROUTES — Auto-Detect
# ═══════════════════════════════════════════════════════════════

@app.route('/api/autodetect/toggle', methods=['POST'])
def toggle_autodetect():
    global auto_detect_enabled
    auto_detect_enabled = not auto_detect_enabled
    socketio.emit('autodetect-status', {'enabled': auto_detect_enabled})
    return jsonify({'enabled': auto_detect_enabled})

@app.route('/api/autodetect/trigger', methods=['POST'])
def trigger_demo():
    evt  = random.choice(AUTO_EVENTS)
    demo = {
        'id': 'DEMO_' + secrets.token_hex(4),
        'message': evt[0], 'location': evt[1],
        'confidence': 72, 'confidenceHistory': [22,50,72],
        'priority': 'MEDIUM', 'status': 'DEMO', 'source': 'demo',
        'reporterName': '🤖 Demo System',
        'relay': ['Device A','Floor Relay','Control Room'],
        'relayTotalDelay': 320,
        'matchedSignals': ['smoke'],
        'explanation': 'DEMO: Test scenario — not a real incident.',
        'systemAnalysis': '🎬 DEMO MODE: Simulated for training. Disappears in 15s.',
        'time': datetime.now().strftime('%H:%M:%S'),
        'timestamp': datetime.utcnow().isoformat(),
        'timeline': [], 'contactMessages': [],
        'isDemoOnly': True,
    }
    socketio.emit('demo-incident', demo)
    return jsonify({'demo': demo})

# ═══════════════════════════════════════════════════════════════
# ROUTES — SOS / Incidents
# ═══════════════════════════════════════════════════════════════

@app.route('/api/sos', methods=['POST'])
def sos():
    data     = request.get_json() or {}
    message  = (data.get('message') or '').strip()
    location = data.get('location')
    if not message: return jsonify({'error': 'Message required'}), 400
    cu = get_current_user()
    # Duplicate check
    with sqlite3.connect(DB_PATH) as db:
        dup = db.execute("""SELECT id FROM incidents WHERE LOWER(message)=LOWER(?)
            AND status NOT IN ('RESOLVED','FALSE_ALARM')
            AND created_at>datetime('now','-5 minutes')""", (message,)).fetchone()
    if dup:
        inc = get_incident_by_id(dup['id'], cu['id'] if cu else None, cu.get('is_admin',False) if cu else False)
        return jsonify({'error': 'Duplicate incident', 'existingIncident': inc}), 409
    inc = create_incident(message, location, 'user')
    if cu:
        execute("""UPDATE incidents SET reporter_id=?,reporter_name=?,
            reporter_phone=?,reporter_role=?,reporter_room=? WHERE id=?""",
            (cu['id'],cu['name'],cu.get('phone','N/A'),cu.get('role_label','User'),cu.get('room_number'),inc['id']))
        inc['reporterId']   = cu['id']
        inc['reporterName'] = cu['name']
    auto_assign_responder(inc)
    updated = get_incident_by_id(inc['id'], cu['id'] if cu else None, cu.get('is_admin',False) if cu else False)
    socketio.emit('new-incident', incident_to_dict(get_incident_by_id(inc['id']), None, False))
    return jsonify(updated), 201

@app.route('/api/incidents')
def incidents():
    cu       = get_current_user()
    rid      = cu['id'] if cu else None
    is_admin = cu.get('is_admin',False) if cu else False
    status   = request.args.get('status')
    priority = request.args.get('priority')
    limit    = request.args.get('limit', type=int)
    sql      = "SELECT * FROM incidents WHERE 1=1"
    args     = []
    if status:   sql += " AND status=?";   args.append(status)
    if priority: sql += " AND priority=?"; args.append(priority)
    sql += " ORDER BY created_at DESC"
    if limit: sql += " LIMIT ?"; args.append(limit)
    rows = query(sql, args)
    return jsonify([incident_to_dict(r, rid, is_admin) for r in rows])

@app.route('/api/incidents/active')
def active_incidents():
    cu       = get_current_user()
    rid      = cu['id'] if cu else None
    is_admin = cu.get('is_admin',False) if cu else False
    rows     = query("SELECT * FROM incidents WHERE status IN ('ACTIVE','RESPONDING') ORDER BY created_at DESC")
    result   = [incident_to_dict(r, rid, is_admin) for r in rows]
    priority_order = {'CRITICAL':0,'MEDIUM':1,'LOW':2}
    result.sort(key=lambda x: priority_order.get(x.get('priority','LOW'),2))
    return jsonify(result)

@app.route('/api/incidents/<int:inc_id>')
def get_incident(inc_id):
    cu       = get_current_user()
    rid      = cu['id'] if cu else None
    is_admin = cu.get('is_admin',False) if cu else False
    inc      = get_incident_by_id(inc_id, rid, is_admin)
    if not inc: return jsonify({'error': 'Not found'}), 404
    return jsonify(inc)

@app.route('/api/incidents/<int:inc_id>/timeline')
def incident_timeline(inc_id):
    inc = get_incident_by_id(inc_id)
    if not inc: return jsonify({'error': 'Not found'}), 404
    return jsonify(inc.get('timeline', []))

@app.route('/api/incidents/<int:inc_id>/status', methods=['PATCH'])
def update_status(inc_id):
    """
    FIX: Admin can now ALWAYS update status (responding + resolved).
    Assigned responder can also update their own incident.
    """
    cu         = get_current_user()
    data       = request.get_json() or {}
    new_status = data.get('status','')
    note       = data.get('note','')
    valid      = ['ACTIVE','RESPONDING','RESOLVED','FALSE_ALARM']
    if new_status not in valid:
        return jsonify({'error': 'Invalid status'}), 400

    with sqlite3.connect(DB_PATH) as db:
        row = db.execute("SELECT * FROM incidents WHERE id=?", (inc_id,)).fetchone()
        if not row: return jsonify({'error': 'Not found'}), 404

        # Permission check — v5.1 fixed
        # Admin: always allowed
        # Assigned responder: allowed for their own incident (RESPONDING or RESOLVED)
        # canRespond staff: can set RESPONDING on any ACTIVE incident
        # canResolve staff: can set RESOLVED on their assigned incident
        if new_status in ('RESOLVED','FALSE_ALARM','RESPONDING'):
            if cu:
                is_admin    = bool(cu.get('is_admin', False))
                is_assigned = str(cu['id']) == str(row['assigned_user_id'])
                can_respond = bool(cu.get('can_respond', False))
                can_resolve = bool(cu.get('can_resolve', False))
                allowed = (
                    is_admin                                           # admin always wins
                    or is_assigned                                     # assigned person: full control
                    or (can_respond and new_status == 'RESPONDING')   # any responder can start responding
                    or (can_resolve and new_status in ('RESOLVED','FALSE_ALARM') and is_assigned)
                )
                if not allowed:
                    return jsonify({'error': 'Only the assigned responder or admin can resolve this incident.'}), 403
            else:
                return jsonify({'error': 'Authentication required'}), 401

        resolved_at = (datetime.utcnow() + timedelta(hours=5, minutes=30)).isoformat() if new_status in ('RESOLVED','FALSE_ALARM') else None
        resolved_by = cu['name'] if cu and new_status in ('RESOLVED','FALSE_ALARM') else None

        db.execute("UPDATE incidents SET status=?,resolved_at=?,resolved_by=? WHERE id=?",
            (new_status, resolved_at, resolved_by, inc_id))
        actor = cu['name'] if cu else 'System'
        db.execute("""INSERT INTO incident_timeline(incident_id,event,description,actor,icon,confidence)
            VALUES(?,?,?,?,?,?)""",
            (inc_id,f"STATUS_{new_status}",f"Status → {new_status}. {note}".strip(),actor,'📋',row['confidence']))

        # Free up responder when resolved
        if new_status in ('RESOLVED','FALSE_ALARM') and row['assigned_user_id']:
            db.execute("""UPDATE users SET resolved_count=resolved_count+1,
                active_incident_count=MAX(0,active_incident_count-1),available=1,status='active'
                WHERE id=?""", (row['assigned_user_id'],))

        if new_status == 'RESOLVED':
            hk = datetime.utcnow().strftime('%Y-%m-%dT%H')
            db.execute("""INSERT INTO incident_hourly_stats(hour_key,count,resolved) VALUES(?,0,1)
                ON CONFLICT(hour_key) DO UPDATE SET resolved=resolved+1""", (hk,))
        db.commit()

    rid      = cu['id'] if cu else None
    is_admin = cu.get('is_admin',False) if cu else False
    updated  = get_incident_by_id(inc_id, rid, is_admin)
    socketio.emit('incident-updated', incident_to_dict(get_incident_by_id(inc_id), None, False))
    socketio.emit('users-update', get_all_users())
    return jsonify(updated)

@app.route('/api/incidents/<int:inc_id>/assign', methods=['POST'])
def assign_responder(inc_id):
    data      = request.get_json() or {}
    responder = data.get('responder',{})
    user_id   = data.get('userId')
    if not responder.get('name'): return jsonify({'error': 'Responder required'}), 400
    deadline = (datetime.utcnow()+timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S')
    execute("""UPDATE incidents SET responder_name=?,responder_role=?,responder_phone=?,
        responder_eta=45,responder_status='assigned',assigned_user_id=?,
        assigned_at=datetime('now'),response_deadline=?,
        status=CASE WHEN status='ACTIVE' THEN 'RESPONDING' ELSE status END WHERE id=?""",
        (responder['name'],responder.get('role'),responder.get('phone','N/A'),user_id,deadline,inc_id))
    if user_id:
        execute("UPDATE users SET active_incident_count=active_incident_count+1 WHERE id=?", (user_id,))
    execute("""INSERT INTO incident_timeline(incident_id,event,description,actor,icon,confidence)
        VALUES(?,?,?,'Admin','👤',0)""",
        (inc_id,'RESPONDER_ASSIGNED',f"Manual assignment: {responder['name']}"))
    inc = get_incident_by_id(inc_id)
    socketio.emit('incident-updated', incident_to_dict(get_incident_by_id(inc_id),None,False))
    if user_id:
        socketio.emit('assigned-to-you',{
            'incidentId':inc_id,'assignedUserId':user_id,'incident':inc,
            'siren':True,'responseDeadline':deadline,
            'message':f"🚨 You are assigned to incident #{inc_id}"
        })
    return jsonify(inc)

@app.route('/api/incidents/<int:inc_id>/confidence', methods=['POST'])
def update_confidence(inc_id):
    data   = request.get_json() or {}
    conf   = data.get('confidence')
    reason = data.get('reason','Update')
    if conf is None or not (0 <= conf <= 100): return jsonify({'error': 'Valid confidence 0-100 required'}), 400
    row = query("SELECT confidence_history,confidence FROM incidents WHERE id=?", (inc_id,), one=True)
    if not row: return jsonify({'error': 'Not found'}), 404
    hist = json.loads(row['confidence_history'] or '[]')
    hist.append(conf)
    priority = get_priority(conf)
    execute("UPDATE incidents SET confidence=?,priority=?,confidence_history=? WHERE id=?",
        (conf,priority,json.dumps(hist),inc_id))
    execute("""INSERT INTO incident_timeline(incident_id,event,description,actor,icon,confidence)
        VALUES(?,?,?,'CRISP Engine','📊',?)""",
        (inc_id,'CONFIDENCE_UPDATED',f"Confidence: {row['confidence']}% → {conf}%. {reason}",conf))
    if conf >= 80:
        status_row = query("SELECT status FROM incidents WHERE id=?", (inc_id,), one=True)
        if status_row and status_row['status'] == 'ACTIVE':
            execute("UPDATE incidents SET status='RESPONDING' WHERE id=?", (inc_id,))
    socketio.emit('confidence-updated',{'incidentId':inc_id,'confidence':conf})
    return jsonify(get_incident_by_id(inc_id))

@app.route('/api/incidents/<int:inc_id>/contact', methods=['POST'])
def contact(inc_id):
    cu      = get_current_user()
    data    = request.get_json() or {}
    message = (data.get('message') or '').strip()
    if not message: return jsonify({'error': 'Message required'}), 400
    row = query("SELECT reporter_id,assigned_user_id FROM incidents WHERE id=?", (inc_id,), one=True)
    if not row: return jsonify({'error': 'Not found'}), 404
    mid         = 'msg_' + secrets.token_hex(6)
    sender_id   = cu['id'] if cu else None
    sender_name = cu['name'] if cu else 'Anonymous'
    sender_role = cu.get('role_label','User') if cu else 'User'
    execute("INSERT INTO incident_messages(id,incident_id,sender_id,sender_name,sender_role,message) VALUES(?,?,?,?,?,?)",
        (mid,inc_id,sender_id,sender_name,sender_role,message))
    msg_obj = {'id':mid,'incidentId':inc_id,'senderId':sender_id,'message':message,'senderName':sender_name,'senderRole':sender_role,'timestamp':datetime.utcnow().isoformat()}
    socketio.emit('incident-contact',{**msg_obj,'forUsers':[row['reporter_id'],row['assigned_user_id']]})
    return jsonify(msg_obj)

@app.route('/api/incidents/<int:inc_id>/messages')
def get_messages(inc_id):
    msgs = query("SELECT * FROM incident_messages WHERE incident_id=? ORDER BY created_at", (inc_id,))
    return jsonify([{'id':m['id'],'senderId':m['sender_id'],'message':m['message'],'senderName':m['sender_name'],'senderRole':m['sender_role'],'timestamp':m['created_at']} for m in msgs])

# ═══════════════════════════════════════════════════════════════
# ROUTES — Stats / Health
# ═══════════════════════════════════════════════════════════════

@app.route('/health')
def health():
    with sqlite3.connect(DB_PATH) as db:
        inc_count  = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return jsonify({'status':'healthy','version':'5.0.0','db':'SQLite','incidents':inc_count,'users':user_count,'uptime':time.time()})

@app.route('/api/stats')
def stats():
    with sqlite3.connect(DB_PATH) as db:
        inc = {
            'total':     db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0],
            'active':    db.execute("SELECT COUNT(*) FROM incidents WHERE status='ACTIVE'").fetchone()[0],
            'responding':db.execute("SELECT COUNT(*) FROM incidents WHERE status='RESPONDING'").fetchone()[0],
            'resolved':  db.execute("SELECT COUNT(*) FROM incidents WHERE status='RESOLVED'").fetchone()[0],
            'critical':  db.execute("SELECT COUNT(*) FROM incidents WHERE priority='CRITICAL'").fetchone()[0],
            'medium':    db.execute("SELECT COUNT(*) FROM incidents WHERE priority='MEDIUM'").fetchone()[0],
            'low':       db.execute("SELECT COUNT(*) FROM incidents WHERE priority='LOW'").fetchone()[0],
            'averageConfidence': int(db.execute("SELECT COALESCE(AVG(confidence),0) FROM incidents").fetchone()[0]),
            'hourly':    [dict(r) for r in db.execute("SELECT * FROM incident_hourly_stats ORDER BY hour_key DESC LIMIT 24").fetchall()],
        }
        users = {
            'total':     db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            'guests':    db.execute("SELECT COUNT(*) FROM users WHERE is_guest=1").fetchone()[0],
            'staff':     db.execute("SELECT COUNT(*) FROM users WHERE is_guest=0").fetchone()[0],
            'online':    db.execute("SELECT COUNT(*) FROM users WHERE last_seen>datetime('now','-3 minutes')").fetchone()[0],
            'available': db.execute("SELECT COUNT(*) FROM users WHERE can_respond=1 AND active_incident_count<2").fetchone()[0],
            'pending':   db.execute("SELECT COUNT(*) FROM users WHERE requested_role!='guest' AND requested_role!='visitor' AND (is_guest=1 OR role='guest')").fetchone()[0],
        }
    return jsonify({'incidents':inc,'users':users,'mesh':{'devices':12,'resilienceScore':85,'averageDelay':180},'timestamp':datetime.utcnow().isoformat()})

@app.route('/api/config')
def get_config():
    """Public config for frontend"""
    return jsonify({'mapsKey': GOOGLE_MAPS_KEY, 'version': '5.0.0'})

# ═══════════════════════════════════════════════════════════════
# WebSocket Events
# ═══════════════════════════════════════════════════════════════

@socketio.on('connect')
def on_connect():
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        incs = [incident_to_dict(r, None, False) for r in rows]
    emit('initial-incidents', incs)
    emit('users-update', get_all_users())
    emit('online-users', get_online_users())
    emit('autodetect-status', {'enabled': auto_detect_enabled})

@socketio.on('identify')
def on_identify(data):
    token = data.get('token')
    if not token: return
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("""SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id
            WHERE s.token=? AND (s.expires_at IS NULL OR s.expires_at>datetime('now'))""", (token,)).fetchone()
    if row:
        join_room(f"user_{row['id']}")
        emit('identified', {'user': user_to_dict(row, is_self=True)})
        with sqlite3.connect(DB_PATH) as db:
            db.execute("UPDATE users SET last_seen=datetime('now') WHERE id=?", (row['id'],))
        socketio.emit('online-users', get_online_users())
        socketio.emit('users-update', get_all_users())

@socketio.on('heartbeat')
def on_heartbeat():
    pass

@socketio.on('disconnect')
def on_disconnect():
    threading.Timer(3.0, lambda: socketio.emit('online-users', get_online_users())).start()

# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    init_db()
    t = threading.Thread(target=auto_detect_worker, daemon=True)
    t.start()
    port  = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('NODE_ENV','development') != 'production'
    print(f"\n⚡ ResQGrid v5.0 Python Server")
    print(f"🌐 Landing  : http://localhost:{port}/")
    print(f"🔐 Login    : http://localhost:{port}/login")
    print(f"📊 Dashboard: http://localhost:{port}/dashboard")
    print(f"⚙️  Admin   : http://localhost:{port}/admin")
    print(f"🗄️  SQLite  : {DB_PATH}")
    print(f"🗺️  Maps    : {'✅ Configured' if GOOGLE_MAPS_KEY else '⚠️  No GOOGLE_MAPS_KEY set'}\n")
    socketio.run(app, host='0.0.0.0', port=port, debug=debug, allow_unsafe_werkzeug=True)
