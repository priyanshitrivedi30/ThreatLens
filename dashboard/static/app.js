// ── STATE ─────────────────────────────────────────────
let threshold = 5;
let liveCount = 0;
let sseConn   = null;
let apiBase   = window.location.origin;
let allIPs    = [];
let firedAlerts = [];   // alerts shown in the panel

const ts = () => new Date().toLocaleTimeString('en-GB', { hour12: false });

// ── DESKTOP NOTIFICATIONS ─────────────────────────────

async function requestNotifPermission() {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'default') {
    await Notification.requestPermission();
  }
}

function desktopNotify(ip, attempts, country, city) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const flag    = countryFlag(country) || '🌐';
  const loc     = city ? `${city}, ${country}` : (country || 'Unknown');
  const n = new Notification('🚨 ThreatLens — CRITICAL IP', {
    body:    `${ip}\n${attempts} attempts · ${flag} ${loc}`,
    icon:    '/static/icon.png',   // optional — ignored if missing
    tag:     ip,                   // deduplicate: one notif per IP
    requireInteraction: false,
  });
  n.onclick = () => { window.focus(); n.close(); };
}

// ── HELPERS ───────────────────────────────────────────

function setStatus(state, label) {
  const dot = document.getElementById('live-dot');
  const txt = document.getElementById('status-txt');
  dot.className = 'dot ' + (state === 'live' ? 'live' : state === 'err' ? 'err' : '');
  txt.textContent = label || state.toUpperCase();
  txt.style.color = state === 'live' ? 'var(--success)' : state === 'err' ? 'var(--danger)' : 'var(--textdim)';
}

function flashEl(id, val) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = typeof val === 'number' ? val.toLocaleString() : val;
  el.classList.remove('flash');
  void el.offsetWidth;
  el.classList.add('flash');
}

function countryFlag(code) {
  if (!code || code.length !== 2) return '';
  return code.toUpperCase().replace(/./g, c =>
    String.fromCodePoint(0x1F1E0 - 65 + c.charCodeAt(0))
  );
}

// ── ALERTS PANEL ──────────────────────────────────────

function showAlertPanel(alerts) {
  const panel = document.getElementById('alerts-panel');
  const body  = document.getElementById('alerts-body');
  const badge = document.getElementById('alerts-badge');

  if (!alerts.length) { panel.style.display = 'none'; return; }

  badge.textContent = alerts.length;
  panel.style.display = 'block';

  body.innerHTML = '';
  alerts.forEach(a => {
    const flag = countryFlag(a.country_code || a.country);
    const loc  = a.city ? `${a.city}, ${a.country}` : (a.country || '??');
    const card = document.createElement('div');
    card.className = 'alert-card';
    card.innerHTML = `
      <span class="alert-icon">🚨</span>
      <span class="alert-ip">${a.ip}</span>
      <span class="alert-att">${a.attempts} attempts</span>
      <span class="alert-geo">${flag} ${loc}</span>
      ${a.fired_at ? `<span class="alert-time">${a.fired_at}</span>` : ''}`;
    body.appendChild(card);
  });
}

function dismissAlerts() {
  document.getElementById('alerts-panel').style.display = 'none';
}

async function fetchAlerts() {
  try {
    const r = await fetch(`${apiBase}/api/alerts`);
    if (!r.ok) return;
    const data = await r.json();
    firedAlerts = data.alerts || [];
    showAlertPanel(firedAlerts);
  } catch {}
}

// ── SSE LIVE FEED ─────────────────────────────────────

function connectSSE() {
  if (sseConn) sseConn.close();
  const url = `${apiBase}/api/feed`;
  try {
    sseConn = new EventSource(url);
    sseConn.onopen = () => {
      document.getElementById('feed-box').innerHTML = '';
      addFeedLine('sys', `connected → ${url}`);
    };
    sseConn.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data);

        if (ev.type === 'alert') {
          // New CRITICAL IP — show desktop notification + update panel
          desktopNotify(ev.ip, ev.attempts, ev.country, ev.city);
          firedAlerts.unshift(ev);
          showAlertPanel(firedAlerts);
          addFeedLine('alert', null, ev);
          return;
        }

        // Normal attack event
        liveCount++;
        flashEl('s-live', liveCount);
        addFeedLine('attack', null, ev);
      } catch {}
    };
    sseConn.onerror = () => addFeedLine('sys', 'reconnecting...');
  } catch (err) {
    addFeedLine('sys', `SSE error: ${err.message}`);
  }
}

function addFeedLine(type, text, ev) {
  const box = document.getElementById('feed-box');
  const div = document.createElement('div');
  div.className = 'fline';

  if (type === 'sys') {
    div.innerHTML = `<span class="fline-sys"># ${text}</span>`;

  } else if (type === 'alert') {
    const flag = countryFlag(ev.country_code || ev.country);
    div.innerHTML = `
      <span class="fline-ts">${ts()}</span>
      <span class="fline-alert">🚨 ALERT</span>
      <span class="fline-ip">${(ev.ip || '').padEnd(16)}</span>
      <span class="fline-att">${ev.attempts} attempts</span>
      ${flag ? `<span class="fline-flag">${flag}</span>` : ''}`;

  } else {
    const flag = countryFlag((ev.country_code || ev.country || '').slice(0, 2));
    div.innerHTML = `
      <span class="fline-ts">${ts()}</span>
      <span class="fline-ip">${(ev.ip || '').padEnd(16)}</span>
      <span class="fline-usr">→ ${ev.user}</span>
      ${flag ? `<span class="fline-flag">${flag}</span>` : ''}`;
  }

  box.appendChild(div);
  while (box.children.length > 100) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}

// ── IP TABLE ──────────────────────────────────────────

function filterTable() {
  const q = (document.getElementById('ip-search')?.value || document.getElementById('tbl-ip-search')?.value || '').toLowerCase();
  renderIPTable(q ? allIPs.filter(d => d.ip.includes(q)) : allIPs);
}

function renderIPTable(ips) {
  const tbody = document.getElementById('ip-tbody');
  tbody.innerHTML = '';
  const maxA = ips.length ? ips[0].attempts : 1;

  ips.forEach((d, i) => {
    const st     = d.status || 'NORMAL';
    const pct    = Math.round((d.attempts / maxA) * 100);
    const barCls = st === 'CRITICAL' ? 'ibar-r' : st === 'FLAGGED' ? 'ibar-o' : 'ibar-b';
    const bdgCls = st === 'CRITICAL' ? 'badge-c' : st === 'FLAGGED' ? 'badge-f' : 'badge-n';

    const flag   = countryFlag(d.country_code || d.country);
    const geoStr = d.city ? `${flag} ${d.city}, ${d.country}` : (d.country && d.country !== '??' ? `${flag} ${d.country}` : '—');
    const abuse  = d.abuse_score != null
      ? `<span class="abuse-badge" title="${d.total_reports||0} reports on AbuseIPDB">${d.abuse_score}%</span>`
      : '';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="td-rank">${String(i+1).padStart(2,'0')}</td>
      <td class="td-ip">${d.ip}${abuse}</td>
      <td><div class="ibar"><div class="ibar-track"><div class="ibar-fill ${barCls}" style="width:${pct}%"></div></div></div></td>
      <td class="td-cnt">${d.attempts}</td>
      <td class="td-ctry" title="${d.city||''}">${geoStr}</td>
      <td><span class="badge ${bdgCls}">${st}</span></td>`;
    tbody.appendChild(tr);
  });
}

// ── TIMELINE ──────────────────────────────────────────

function renderTimeline(data) {
  const W=700,H=150,PAD={t:10,r:10,b:28,l:10};
  const cW=W-PAD.l-PAD.r, cH=H-PAD.t-PAD.b;
  const maxV=Math.max(...data,1), n=data.length;
  const xPos=i=>PAD.l+(i/(n-1))*cW;
  const yPos=v=>PAD.t+cH-(v/maxV)*cH;

  const grid=document.getElementById('tl-grid');
  grid.innerHTML='';
  [0.25,0.5,0.75,1].forEach(f=>{
    const y=PAD.t+cH-f*cH;
    const line=document.createElementNS('http://www.w3.org/2000/svg','line');
    line.setAttribute('x1',PAD.l);line.setAttribute('x2',W-PAD.r);
    line.setAttribute('y1',y);line.setAttribute('y2',y);
    line.setAttribute('stroke','#1a2035');line.setAttribute('stroke-width','0.5');
    grid.appendChild(line);
  });

  const pts=data.map((v,i)=>[xPos(i),yPos(v)]);
  function smooth(p){
    if(p.length<2)return'';
    let d=`M ${p[0][0]},${p[0][1]}`;
    for(let i=0;i<p.length-1;i++){
      const p0=p[Math.max(i-1,0)],p1=p[i],p2=p[i+1],p3=p[Math.min(i+2,p.length-1)];
      const cp1x=p1[0]+(p2[0]-p0[0])/6,cp1y=p1[1]+(p2[1]-p0[1])/6;
      const cp2x=p2[0]-(p3[0]-p1[0])/6,cp2y=p2[1]-(p3[1]-p1[1])/6;
      d+=` C ${cp1x},${cp1y} ${cp2x},${cp2y} ${p2[0]},${p2[1]}`;
    }
    return d;
  }

  const linePath=smooth(pts);
  const areaPath=linePath+` L ${xPos(n-1)},${PAD.t+cH} L ${xPos(0)},${PAD.t+cH} Z`;
  const peak=Math.max(...data)/maxV;
  const lineColor=peak>0.8?'#ff2d55':peak>0.5?'#ff9500':'#00c8ff';

  document.getElementById('tl-area').setAttribute('d',areaPath);
  document.getElementById('tl-area').setAttribute('fill',peak>0.5?'url(#grad-danger)':'url(#grad-area)');
  document.getElementById('tl-line').setAttribute('d',linePath);
  document.getElementById('tl-line').setAttribute('stroke',lineColor);

  const dotsG=document.getElementById('tl-dots');dotsG.innerHTML='';
  const peakV=Math.max(...data);
  data.forEach((v,i)=>{
    if(v!==peakV&&i%6!==0)return;
    const c=document.createElementNS('http://www.w3.org/2000/svg','circle');
    c.setAttribute('cx',xPos(i));c.setAttribute('cy',yPos(v));
    c.setAttribute('r',v===peakV?'4':'2.5');
    c.setAttribute('fill',v===peakV?lineColor:'#0a0d14');
    c.setAttribute('stroke',lineColor);c.setAttribute('stroke-width',v===peakV?'0':'1.5');
    if(v===peakV)c.setAttribute('filter','url(#glow-dot)');
    dotsG.appendChild(c);
  });

  const labsG=document.getElementById('tl-labels');labsG.innerHTML='';
  [0,6,12,18,23].forEach(i=>{
    const t=document.createElementNS('http://www.w3.org/2000/svg','text');
    t.setAttribute('x',xPos(i));t.setAttribute('y',H-6);
    t.setAttribute('text-anchor','middle');t.setAttribute('fill','#5a6a80');
    t.setAttribute('font-size','8');t.setAttribute('font-family','Fira Code,monospace');
    t.textContent=`${String(i).padStart(2,'0')}:00`;
    labsG.appendChild(t);
  });

  const hitsG=document.getElementById('tl-hits');hitsG.innerHTML='';
  const tooltip=document.getElementById('tl-tooltip');
  const hline=document.getElementById('tl-hline');
  const svgEl=document.getElementById('timeline-svg');
  const barW=cW/n;
  data.forEach((v,i)=>{
    const rect=document.createElementNS('http://www.w3.org/2000/svg','rect');
    rect.setAttribute('x',xPos(i)-barW/2);rect.setAttribute('y',PAD.t);
    rect.setAttribute('width',barW);rect.setAttribute('height',cH);
    rect.setAttribute('fill','transparent');rect.style.cursor='crosshair';
    rect.addEventListener('mouseenter',()=>{
      const sr=svgEl.getBoundingClientRect(),wr=svgEl.closest('.timeline-wrap').getBoundingClientRect();
      hline.setAttribute('x1',xPos(i));hline.setAttribute('x2',xPos(i));hline.setAttribute('opacity','1');
      tooltip.style.opacity='1';tooltip.textContent=`${String(i).padStart(2,'0')}:00 — ${v} attempts`;
      tooltip.style.left=Math.min((xPos(i)/W)*sr.width+sr.left-wr.left+8,sr.width-160)+'px';
      tooltip.style.top='10px';
    });
    rect.addEventListener('mouseleave',()=>{hline.setAttribute('opacity','0');tooltip.style.opacity='0';});
    hitsG.appendChild(rect);
  });
}

// ── GEO PANEL ─────────────────────────────────────────

function renderGeoPanel(ips) {
  const box = document.getElementById('geo-box');
  if (!box) return;
  const byCountry = {};
  ips.forEach(d => {
    if (!d.country || d.country === '??') return;
    if (!byCountry[d.country]) byCountry[d.country] = { att: 0, code: d.country_code || '' };
    byCountry[d.country].att += d.attempts;
  });
  const sorted = Object.entries(byCountry).sort((a,b)=>b[1].att-a[1].att).slice(0,10);
  if (!sorted.length) { box.innerHTML = '<div class="geo-empty">Geo data loading…</div>'; return; }
  const maxA = sorted[0][1].att;
  box.innerHTML = '';
  sorted.forEach(([country, data]) => {
    const pct  = Math.round((data.att / maxA) * 100);
    const flag = countryFlag(data.code || country.slice(0,2));
    const row  = document.createElement('div');
    row.className = 'cred-row';
    row.innerHTML = `
      <span class="cred-rank">${flag}</span>
      <span class="cred-name usr">${country}</span>
      <div class="cred-bar"><div class="cred-fill usr" style="width:${pct}%"></div></div>
      <span class="cred-cnt">${data.att.toLocaleString()}</span>`;
    box.appendChild(row);
  });
}

// ── DETECTION LOG ─────────────────────────────────────

function logLine(cls, msg) {
  const box = document.getElementById('log-box');
  const div = document.createElement('div');
  div.className = cls;
  div.textContent = `[${ts()}] ${msg}`;
  box.appendChild(div);
  while (box.children.length > 60) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}

// ── MAIN RENDER ───────────────────────────────────────

function render(data) {
  allIPs    = data.ips || [];
  threshold = data.threshold || threshold;

  flashEl('h-total',   data.total_events  || 0);
  flashEl('h-flagged', data.flagged_count || 0);
  flashEl('h-unique',  data.unique_ips    || 0);
  flashEl('s-total',   data.total_events  || 0);
  flashEl('s-flagged', data.flagged_count || 0);
  flashEl('s-unique',  data.unique_ips    || 0);
  flashEl('s-thresh',  threshold);

  document.getElementById('last-update').textContent = ts();
  document.getElementById('src-tag').textContent     = '// ' + (data.source || 'unknown');
  document.getElementById('ip-count').textContent    = allIPs.length + ' entries';

  filterTable();
  renderTimeline(data.timeline || Array(24).fill(0));
  renderGeoPanel(allIPs);

  // Usernames
  const ubox = document.getElementById('user-box');
  ubox.innerHTML = '';
  const users = data.usernames || [];
  const maxU  = users.length ? users[0].count : 1;
  users.forEach((u, i) => {
    const pct = Math.round((u.count / maxU) * 100);
    const row = document.createElement('div');
    row.className = 'cred-row';
    row.innerHTML = `
      <span class="cred-rank">${String(i+1).padStart(2,'0')}</span>
      <span class="cred-name usr">${u.name}</span>
      <div class="cred-bar"><div class="cred-fill usr" style="width:${pct}%"></div></div>
      <span class="cred-cnt">${u.count}</span>`;
    ubox.appendChild(row);
  });

  // Detection log
  const logBox = document.getElementById('log-box');
  logBox.innerHTML = '';
  logLine('ld', `scan complete · threshold=${threshold} · source=${data.source || '?'}`);
  allIPs.slice(0, 20).forEach(d => {
    const st  = d.status || 'NORMAL';
    const geo = d.city ? ` · ${d.city}, ${d.country}` : (d.country && d.country !== '??' ? ` · ${d.country}` : '');
    const abuse = d.abuse_score != null ? ` · abuse=${d.abuse_score}%` : '';
    if (st === 'CRITICAL')     logLine('la', `[CRITICAL] ${d.ip} — ${d.attempts} attempts${geo}${abuse}`);
    else if (st === 'FLAGGED') logLine('lw', `[FLAGGED]  ${d.ip} — ${d.attempts} attempts${geo}${abuse}`);
    else                       logLine('li', `[NORMAL]   ${d.ip} — ${d.attempts} attempts${geo}`);
  });
  logLine('ls', `[DONE] ${allIPs.length} IPs · ${data.flagged_count} flagged · ${data.total_events} total events`);
}

// ── FETCH ─────────────────────────────────────────────

async function fetchStats() {
  const custom = document.getElementById('custom-url').value.trim();
  if (custom) apiBase = custom.replace(/\/$/, '');
  threshold = parseInt(document.getElementById('threshold').value);

  try {
    const res = await fetch(`${apiBase}/api/stats?threshold=${threshold}`, { signal: AbortSignal.timeout(7000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    render(await res.json());
    setStatus('live', 'LIVE');
  } catch (e) {
    setStatus('err', 'ERROR');
    logLine('la', `[ERR] ${e.message}`);
  }
}

function manualRefresh() { fetchStats(); fetchAlerts(); }

// ── INIT ──────────────────────────────────────────────

requestNotifPermission();
setStatus('', 'CONNECTING');
fetchStats();
fetchAlerts();
connectSSE();
setInterval(fetchStats,  15000);
setInterval(fetchAlerts, 30000);

document.getElementById('threshold').addEventListener('change', fetchStats);
document.getElementById('custom-url').addEventListener('keydown', e => {
  if (e.key === 'Enter') { fetchStats(); connectSSE(); }
});
