#pragma once
// ═══════════════════════════════════════════════════════════════════════════════
//  portal_html.h — v5.5.0 Bitwarden-style responsive webapp
//  Desktop: 3-column (type sidebar + entries list + detail panel)
//  Mobile: hamburger menu + scrollable list + modal detail
// ═══════════════════════════════════════════════════════════════════════════════

static const char PORTAL_HTML[] PROGMEM = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="referrer" content="no-referrer">
<title>SecureVault</title>
<style>
:root{--bg:#1c1d21;--sidebar:#16171b;--sidebar-hover:#232429;--panel:#26272c;--panel-hover:#2c2d33;--border:#3a3b42;--text:#e8e8ea;--muted:#9a9aa3;--accent:#4c8dff;--accent2:#3b74e0;--danger:#f87171;--success:#34d399;--fav:#fbbf24;--radius:8px;--type-login:#4c8dff;--type-card:#a78bfa;--type-identity:#34d399;--type-note:#fbbf24;--input-bg:#2c2d33;--input-bg-focus:#313239;--selected-bg:rgba(76,141,255,.15);--shadow:rgba(0,0,0,.4)}
[data-theme="light"]{--bg:#f0f2f5;--sidebar:#175ddc;--sidebar-hover:#1a5dc2;--panel:#fff;--panel-hover:#f7fafc;--border:#e2e8f0;--text:#1a202c;--muted:#718096;--accent:#175ddc;--accent2:#1349b8;--danger:#dc2626;--success:#059669;--fav:#f59e0b;--type-login:#3b82f6;--type-card:#8b5cf6;--type-identity:#10b981;--type-note:#f59e0b;--input-bg:#f7fafc;--input-bg-focus:#fff;--selected-bg:#eff6ff;--shadow:rgba(0,0,0,.1)}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);font-size:14px;-webkit-tap-highlight-color:transparent}
button{font-family:inherit;font-size:13px;border:none;border-radius:var(--radius);padding:8px 14px;background:var(--accent);color:#fff;cursor:pointer;transition:all .15s;font-weight:500}
button:hover{background:var(--accent2)}
button.danger{background:var(--danger)}
button.ghost{background:transparent;color:var(--muted);border:1px solid var(--border)}
button.ghost:hover{background:var(--panel-hover);color:var(--text)}
button:disabled{opacity:.5;cursor:not-allowed}
input,select,textarea{font-family:inherit;font-size:14px;background:var(--input-bg);color:var(--text);border:1px solid var(--border);border-radius:var(--radius);padding:8px 12px;width:100%;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--accent);background:var(--input-bg-focus)}
label{display:block;color:var(--muted);font-size:11px;margin-bottom:3px;text-transform:uppercase;letter-spacing:.5px;font-weight:600}
.row{margin-bottom:10px}
.row.split{display:flex;gap:8px}
.row.split>*{flex:1}
#app{height:100dvh;display:flex;overflow:hidden}
/* ── Login screen ── */
#loginScreen{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:var(--bg);z-index:999;align-items:center;justify-content:center}
#loginScreen.active{display:flex}
.login-box{background:var(--panel);border-radius:12px;padding:32px;max-width:360px;width:90%;box-shadow:0 4px 20px var(--shadow)}
.login-box h1{font-size:22px;font-weight:700;color:var(--text);margin-bottom:4px}
.login-box p{color:var(--muted);font-size:13px;margin-bottom:20px}
#codeInput{font-size:32px;text-align:center;letter-spacing:8px;margin-bottom:12px}
#loginError{color:var(--danger);min-height:18px;font-size:12px;margin-bottom:8px}
/* ── Sidebar (type filters) ── */
.sidebar{width:240px;background:var(--sidebar);color:#fff;display:flex;flex-direction:column;overflow:hidden;transition:transform .25s}
.sidebar-header{padding:16px;display:flex;align-items:center;gap:8px;font-weight:700;font-size:16px}
.sidebar-header svg{width:22px;height:22px}
.type-list{flex:1;overflow-y:auto;padding:0 8px}
.type-item{display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:var(--radius);cursor:pointer;font-size:13px;transition:background .15s;margin-bottom:2px}
.type-item:hover{background:rgba(255,255,255,.1)}
.type-item.active{background:rgba(255,255,255,.15);font-weight:600}
.type-item .icon{width:16px;height:16px;flex-shrink:0;opacity:.8}
.type-item .count{margin-left:auto;font-size:11px;opacity:.6}
.sidebar-footer{padding:8px 16px;border-top:1px solid rgba(255,255,255,.1)}
.sidebar-footer button{width:100%;background:rgba(255,255,255,.15)}
.sidebar-footer button:hover{background:rgba(255,255,255,.25)}
/* ── Main content ── */
.main{flex:1;display:flex;overflow:hidden;flex-direction:column}
.main-header{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:var(--panel);border-bottom:1px solid var(--border)}
.main-header h2{font-size:16px;font-weight:600}
.main-header .actions{display:flex;gap:8px;align-items:center}
.search-bar{padding:8px 16px;background:var(--panel);border-bottom:1px solid var(--border)}
.search-bar input{font-size:13px}
.entry-list{flex:1;overflow-y:auto;padding:8px;background:var(--bg)}
.entry-card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);padding:12px;margin-bottom:6px;cursor:pointer;transition:all .15s;display:flex;align-items:center;gap:12px}
.entry-card:hover{border-color:var(--accent);box-shadow:0 2px 8px var(--shadow)}
.entry-card.selected{border-color:var(--accent);background:var(--selected-bg)}
.entry-card .type-icon{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
.entry-card .type-icon.login{background:var(--type-login);color:#fff}
.entry-card .type-icon.card{background:var(--type-card);color:#fff}
.entry-card .type-icon.identity{background:var(--type-identity);color:#fff}
.entry-card .type-icon.note{background:var(--type-note);color:#fff}
.entry-card .info{flex:1;min-width:0}
.entry-card .name{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.entry-card .sub{color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.entry-card .fav-star{color:var(--fav);font-size:14px;flex-shrink:0}
.entry-card .menu-btn{color:var(--muted);font-size:18px;padding:4px 8px;cursor:pointer}
.empty{text-align:center;color:var(--muted);padding:48px 16px;font-size:14px}
/* ── Detail panel (desktop) ── */
.detail-panel{width:360px;background:var(--panel);border-left:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
.detail-header{display:flex;align-items:center;justify-content:space-between;padding:16px;border-bottom:1px solid var(--border)}
.detail-header h3{font-size:16px;font-weight:600}
.detail-content{flex:1;overflow-y:auto;padding:16px}
.detail-empty{display:flex;align-items:center;justify-content:center;height:100%;color:var(--muted);text-align:center;font-size:14px}
.detail-field{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);font-size:13px}
.detail-field-label{color:var(--muted);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px}
.detail-field-value{color:var(--text);font-family:monospace;word-break:break-all;text-align:right;max-width:65%;cursor:pointer}
.detail-field-value.secret{color:var(--accent)}
.detail-actions{display:flex;gap:8px;padding:16px;border-top:1px solid var(--border)}
/* ── Mobile: hamburger ── */
.hamburger{display:none;position:fixed;top:12px;left:12px;z-index:50;width:40px;height:40px;border-radius:8px;background:var(--panel);border:1px solid var(--border);align-items:center;justify-content:center;cursor:pointer;font-size:20px;box-shadow:0 2px 8px var(--shadow)}
.overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.4);z-index:40}
.overlay.active{display:block}
.fab{display:none}
/* ── Modals ── */
.modal-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:100;align-items:center;justify-content:center;padding:16px}
.modal-overlay.active{display:flex}
.modal{background:var(--panel);border-radius:12px;padding:20px;width:100%;max-width:480px;max-height:85vh;overflow-y:auto;box-shadow:0 8px 30px var(--shadow)}
.modal h3{margin-bottom:16px;font-size:16px;font-weight:600}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
.toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:var(--panel);border:1px solid var(--border);padding:8px 16px;border-radius:var(--radius);z-index:200;display:none;font-size:13px;box-shadow:0 4px 12px var(--shadow)}
.toast.show{display:block}
.toast.error{border-color:var(--danger);color:var(--danger)}
.toast.success{border-color:var(--success);color:var(--success)}
/* ── Responsive ── */
@media(max-width:767px){
  .sidebar{position:fixed;left:0;top:0;bottom:0;z-index:45;transform:translateX(-100%)}
  .sidebar.open{transform:translateX(0)}
  .detail-panel{display:none}
  .hamburger{display:flex}
  .main{padding-left:0}
  .main-header{padding-left:60px}
  .fab{display:flex;position:fixed;bottom:16px;right:16px;width:52px;height:52px;border-radius:50%;background:var(--accent);color:#fff;font-size:24px;border:none;box-shadow:0 4px 12px var(--shadow);align-items:center;justify-content:center;cursor:pointer;z-index:50}
  .entry-list{padding-bottom:80px}
}
@media(min-width:768px){
  .sidebar{transform:translateX(0)}
  .hamburger{display:none}
  .overlay{display:none!important}
}
</style>
</head>
<body>
<div id="app">
<div class="hamburger" onclick="toggleSidebar()">&#9776;</div>
<div class="overlay" id="overlay" onclick="closeSidebar()"></div>
<div class="sidebar" id="sidebar">
  <div class="sidebar-header"><svg viewBox="0 0 24 24" fill="white"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg> SecureVault</div>
  <div class="type-list" id="typeList">
    <div class="type-item active" onclick="setFilter(255)" data-filter="255"><span class="icon">&#128274;</span> All Items <span class="count" id="count-255">0</span></div>
    <div class="type-item" onclick="setFilter(256)" data-filter="256"><span class="icon">&#11088;</span> Favorites <span class="count" id="count-256">0</span></div>
    <div class="type-item" onclick="setFilter(0)" data-filter="0"><span class="icon">&#127760;</span> Login <span class="count" id="count-0">0</span></div>
    <div class="type-item" onclick="setFilter(1)" data-filter="1"><span class="icon">&#128179;</span> Card <span class="count" id="count-1">0</span></div>
    <div class="type-item" onclick="setFilter(2)" data-filter="2"><span class="icon">&#129489;</span> Identity <span class="count" id="count-2">0</span></div>
    <div class="type-item" onclick="setFilter(3)" data-filter="3"><span class="icon">&#128221;</span> Note <span class="count" id="count-3">0</span></div>
    <div class="type-item" onclick="setFilter(254)" data-filter="254"><span class="icon">&#128465;</span> Trash <span class="count" id="count-254">0</span></div>
  </div>
  <div class="sidebar-footer"><button id="themeBtn" class="ghost" style="width:100%;margin-bottom:6px;background:rgba(255,255,255,.15);color:#fff;border:none" onclick="toggleTheme()">&#127769; Light Mode</button><button onclick="doLogout()">Lock Vault</button></div>
</div>
<div class="main">
  <div class="main-header">
    <h2 id="headerTitle">All Items</h2>
    <div class="actions"><button onclick="openAddModal()">+ Add</button></div>
  </div>
  <div class="search-bar"><input id="searchBox" type="text" placeholder="Search vault..." oninput="filterEntries()"></div>
  <div class="entry-list" id="entryList"></div>
</div>
<div class="detail-panel" id="detailPanel">
  <div class="detail-content" id="detailContent"><div class="detail-empty">Select an entry to view details</div></div>
</div>
</div>
<div id="entryModal" class="modal-overlay" onclick="if(event.target===this)closeModal()"><div class="modal">
  <h3 id="modalTitle">Add Entry</h3>
  <div class="row"><label>Type</label><select id="f_type" onchange="renderTypeFields()"><option value="login">Login</option><option value="card">Card</option><option value="identity">Identity</option><option value="note">Note</option></select></div>
  <div class="row"><label>Site / Name</label><input id="f_site" type="text"></div>
  <div id="typeFields"></div>
  <div class="row"><label>Folder</label><input id="f_folder" type="text"></div>
  <div class="row"><label>Notes</label><textarea id="f_notes" rows="3"></textarea></div>
  <div class="row"><label><input type="checkbox" id="f_fav" style="width:auto;margin-right:6px">Mark as Favorite</label></div>
  <div class="modal-actions"><button class="ghost" onclick="closeModal()">Cancel</button><button id="saveBtn" onclick="saveEntry()">Save</button></div>
</div></div>
<div id="deleteModal" class="modal-overlay" onclick="if(event.target===this)closeDeleteModal()"><div class="modal">
  <h3>Delete Entry</h3><p id="deleteMsg" style="color:var(--muted);margin-bottom:8px">Are you sure?</p>
  <div class="modal-actions"><button class="ghost" onclick="closeDeleteModal()">Cancel</button><button class="danger" id="delBtn" onclick="confirmDelete()">Delete</button></div>
</div></div>
<div id="toast" class="toast"></div>
<button class="fab" onclick="openAddModal()">+</button>
<div id="loginScreen" class="active"><div class="login-box">
  <h1>SecureVault</h1>
  <p>Enter the 6-digit code shown on your device</p>
  <input id="codeInput" type="text" inputmode="numeric" maxlength="6" placeholder="000000" autocomplete="off">
  <div id="loginError"></div>
  <button id="loginBtn" onclick="doLogin()" style="width:100%">Connect</button>
</div></div>
<script>
const _K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function _rotr(n,x){return(x>>>n)|(x<<(32-n));}
function sha256(msg){const h=new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);const w=new Uint32Array(64);const l=msg.length;const pl=((l+9+63)>>6)<<6;const pd=new Uint8Array(pl);pd.set(msg);pd[l]=0x80;const bl=l*8;pd[pl-4]=(bl>>>24)&0xff;pd[pl-3]=(bl>>>16)&0xff;pd[pl-2]=(bl>>>8)&0xff;pd[pl-1]=bl&0xff;for(let i=0;i<pl;i+=64){for(let j=0;j<16;j++)w[j]=(pd[i+j*4]<<24)|(pd[i+j*4+1]<<16)|(pd[i+j*4+2]<<8)|pd[i+j*4+3];for(let j=16;j<64;j++){const s0=_rotr(7,w[j-15])^_rotr(18,w[j-15])^(w[j-15]>>>3);const s1=_rotr(17,w[j-2])^_rotr(19,w[j-2])^(w[j-2]>>>10);w[j]=(w[j-16]+s0+w[j-7]+s1)|0;}let a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];for(let j=0;j<64;j++){const S1=_rotr(6,e)^_rotr(11,e)^_rotr(25,e);const ch=(e&f)^(~e&g);const t1=(hh+S1+ch+_K[j]+w[j])|0;const S0=_rotr(2,a)^_rotr(13,a)^_rotr(22,a);const maj=(a&b)^(a&c)^(b&c);const t2=(S0+maj)|0;hh=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}h[0]=(h[0]+a)|0;h[1]=(h[1]+b)|0;h[2]=(h[2]+c)|0;h[3]=(h[3]+d)|0;h[4]=(h[4]+e)|0;h[5]=(h[5]+f)|0;h[6]=(h[6]+g)|0;h[7]=(h[7]+hh)|0;}const out=new Uint8Array(32);for(let i=0;i<8;i++){out[i*4]=(h[i]>>>24)&0xff;out[i*4+1]=(h[i]>>>16)&0xff;out[i*4+2]=(h[i]>>>8)&0xff;out[i*4+3]=h[i]&0xff;}return out;}
function hmacSha256(key,msg){const bs=64;let k=key;if(k.length>bs)k=sha256(k);const pk=new Uint8Array(bs);pk.set(k);const ipad=new Uint8Array(bs),opad=new Uint8Array(bs);for(let i=0;i<bs;i++){ipad[i]=pk[i]^0x36;opad[i]=pk[i]^0x5c;}const inner=new Uint8Array(bs+msg.length);inner.set(ipad);inner.set(msg,bs);const ih=sha256(inner);const outer=new Uint8Array(bs+32);outer.set(opad);outer.set(ih,bs);return sha256(outer);}
// F5: AES-256-GCM pure JS (WebCrypto unavailable over HTTP)
const _SB=[0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];
const _RC=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
function _xt(a){return((a<<1)^((a&0x80)?0x1b:0))&0xff;}
function _aesKE(key){const w=new Uint32Array(60);for(let i=0;i<8;i++)w[i]=(key[4*i]<<24)|(key[4*i+1]<<16)|(key[4*i+2]<<8)|key[4*i+3];for(let i=8;i<60;i++){let t=w[i-1];if(i%8===0){const r=((t<<8)|(t>>>24));t=((_SB[(r>>>24)&0xff]<<24)|(_SB[(r>>>16)&0xff]<<16)|(_SB[(r>>>8)&0xff]<<8)|_SB[r&0xff])^(_RC[(i/8)-1]<<24);}else if(i%8===4){t=(_SB[(t>>>24)&0xff]<<24)|(_SB[(t>>>16)&0xff]<<16)|(_SB[(t>>>8)&0xff]<<8)|_SB[t&0xff];}w[i]=w[i-8]^t;}return w;}
function _aesEB(rk,pt){const s=new Uint8Array(16);s.set(pt);for(let i=0;i<4;i++){const w=rk[i];s[4*i]^=(w>>>24)&0xff;s[4*i+1]^=(w>>>16)&0xff;s[4*i+2]^=(w>>>8)&0xff;s[4*i+3]^=w&0xff;}for(let r=1;r<=13;r++){for(let i=0;i<16;i++)s[i]=_SB[s[i]];const a=s[1],b=s[5],c=s[9],d=s[13];s[1]=b;s[5]=c;s[9]=d;s[13]=a;const e=s[2],f=s[6],g=s[10],h=s[14];s[2]=g;s[6]=h;s[10]=e;s[14]=f;const j=s[3],k=s[7],l=s[11],m=s[15];s[3]=m;s[7]=j;s[11]=k;s[15]=l;for(let c=0;c<4;c++){const i=4*c;const a0=s[i],a1=s[i+1],a2=s[i+2],a3=s[i+3];s[i]=_xt(a0)^_xt(a1)^a1^a2^a3;s[i+1]=a0^_xt(a1)^_xt(a2)^a2^a3;s[i+2]=a0^a1^_xt(a2)^_xt(a3)^a3;s[i+3]=_xt(a0)^a0^a1^a2^_xt(a3);}const o=4*r;for(let i=0;i<4;i++){const w=rk[o+i];s[4*i]^=(w>>>24)&0xff;s[4*i+1]^=(w>>>16)&0xff;s[4*i+2]^=(w>>>8)&0xff;s[4*i+3]^=w&0xff;}}for(let i=0;i<16;i++)s[i]=_SB[s[i]];const a=s[1],b=s[5],c=s[9],d=s[13];s[1]=b;s[5]=c;s[9]=d;s[13]=a;const e=s[2],f=s[6],g=s[10],h=s[14];s[2]=g;s[6]=h;s[10]=e;s[14]=f;const j=s[3],k=s[7],l=s[11],m=s[15];s[3]=m;s[7]=j;s[11]=k;s[15]=l;for(let i=0;i<4;i++){const w=rk[56+i];s[4*i]^=(w>>>24)&0xff;s[4*i+1]^=(w>>>16)&0xff;s[4*i+2]^=(w>>>8)&0xff;s[4*i+3]^=w&0xff;}return s;}
function _gf128(x,y){const z=new Uint8Array(16);const v=new Uint8Array(16);v.set(x);for(let i=0;i<128;i++){if((y[i>>3]>>>(7-(i&7)))&1){for(let j=0;j<16;j++)z[j]^=v[j];}const lsb=v[15]&1;for(let j=15;j>0;j--)v[j]=(v[j]>>>1)|((v[j-1]&1)<<7);v[0]=v[0]>>>1;if(lsb)v[0]^=0xe1;}return z;}
function _xor16(a,b){const r=new Uint8Array(16);for(let i=0;i<16;i++)r[i]=a[i]^b[i];return r;}
function _pad16(d){const r=new Uint8Array(Math.ceil(d.length/16)*16);r.set(d);return r;}
function _ghash(hk,aad,ct){let y=new Uint8Array(16);const ap=_pad16(aad);for(let i=0;i<ap.length;i+=16)y=_gf128(_xor16(y,ap.slice(i,i+16)),hk);const cp=_pad16(ct);for(let i=0;i<cp.length;i+=16)y=_gf128(_xor16(y,cp.slice(i,i+16)),hk);const lb=new Uint8Array(16);const ab=aad.length*8,cb=ct.length*8;lb[4]=(ab>>>24)&0xff;lb[5]=(ab>>>16)&0xff;lb[6]=(ab>>>8)&0xff;lb[7]=ab&0xff;lb[12]=(cb>>>24)&0xff;lb[13]=(cb>>>16)&0xff;lb[14]=(cb>>>8)&0xff;lb[15]=cb&0xff;y=_gf128(_xor16(y,lb),hk);return y;}
function _gcmNonce(ctr){const n=new Uint8Array(12);n[0]=0;n[1]=0;n[2]=0;n[3]=0;n[4]=0;n[5]=0;n[6]=0;n[7]=0;n[8]=(ctr>>>24)&0xff;n[9]=(ctr>>>16)&0xff;n[10]=(ctr>>>8)&0xff;n[11]=ctr&0xff;return n;}
function _gcmAad(ctr){const a=new Uint8Array(8);a[0]=0;a[1]=0;a[2]=0;a[3]=0;a[4]=(ctr>>>24)&0xff;a[5]=(ctr>>>16)&0xff;a[6]=(ctr>>>8)&0xff;a[7]=ctr&0xff;return a;}
function bufToB64(buf){let s='';const a=new Uint8Array(buf);for(let i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s);}
function b64ToBuf(b64){const s=atob(b64);const a=new Uint8Array(s.length);for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return a.buffer;}
function randomHex(n){const a=new Uint8Array(n);crypto.getRandomValues(a);return Array.from(a).map(b=>b.toString(16).padStart(2,'0')).join('');}
function safeLS(k,v){try{if(v===undefined)return localStorage.getItem(k);localStorage.setItem(k,v);}catch(e){return null;}}
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);const b=document.getElementById('themeBtn');if(b)b.innerHTML=t==='light'?'&#127769; Dark Mode':'&#127769; Light Mode';}
function toggleTheme(){const cur=document.documentElement.getAttribute('data-theme')==='light'?'light':'dark';const next=cur==='light'?'dark':'light';safeLS('sv_theme',next);applyTheme(next);}
applyTheme(safeLS('sv_theme')||'dark');
if(window.top!==window.self)window.top.location=window.self.location;
let _s={csrf:null,cid:null,ek:null,mk:null,rx:0,tx:1,paths:{},fh:[]};
let _entries=[],_selIdx=-1,_editIdx=-1,_delIdx=-1;
let _filter=255,_isDesktop=window.matchMedia('(min-width:768px)').matches;
window.matchMedia('(min-width:768px)').addEventListener('change',e=>{_isDesktop=e.matches;renderVault();});
function deriveKeys(code,nonceB64){const nonce=new Uint8Array(b64ToBuf(nonceB64));const cb=new TextEncoder().encode(code);const ei=new Uint8Array(nonce.length+3);ei.set(nonce);ei.set(new TextEncoder().encode("enc"),nonce.length);const mi=new Uint8Array(nonce.length+3);mi.set(nonce);mi.set(new TextEncoder().encode("mac"),nonce.length);_s.ek=hmacSha256(cb,ei);_s.mk=hmacSha256(cb,mi);}
function encryptBody(ptStr){const pt=new TextEncoder().encode(ptStr);const rk=_aesKE(_s.ek);const nonce=_gcmNonce(_s.tx);const aad=_gcmAad(_s.tx);const h0=_aesEB(rk,new Uint8Array(16));const j0=new Uint8Array(16);j0.set(nonce);j0[15]=1;const ct=new Uint8Array(pt.length);let cv=2;for(let i=0;i<pt.length;i+=16){const cb=new Uint8Array(16);cb.set(nonce);cb[12]=(cv>>>24)&0xff;cb[13]=(cv>>>16)&0xff;cb[14]=(cv>>>8)&0xff;cb[15]=cv&0xff;const ec=_aesEB(rk,cb);const n=Math.min(16,pt.length-i);for(let j=0;j<n;j++)ct[i+j]=pt[i+j]^ec[j];cv++;}const s=_ghash(h0,aad,ct);const ej0=_aesEB(rk,j0);const tag=new Uint8Array(16);for(let i=0;i<16;i++)tag[i]=s[i]^ej0[i];return JSON.stringify({counter:_s.tx++,iv:bufToB64(nonce.buffer),ct:bufToB64(ct.buffer),tag:bufToB64(tag.buffer)});}
function decryptBody(fs){const f=JSON.parse(fs);if(f.counter<=_s.rx)throw new Error('Replay');const ct=new Uint8Array(b64ToBuf(f.ct));const tag=new Uint8Array(b64ToBuf(f.tag));if(tag.length!==16)throw new Error('TAG_LEN');const nonce=_gcmNonce(f.counter);const aad=_gcmAad(f.counter);const rk=_aesKE(_s.ek);const h0=_aesEB(rk,new Uint8Array(16));const j0=new Uint8Array(16);j0.set(nonce);j0[15]=1;const s=_ghash(h0,aad,ct);const ej0=_aesEB(rk,j0);let tagOk=true;for(let i=0;i<16;i++)if((s[i]^ej0[i])!==tag[i])tagOk=false;if(!tagOk)throw new Error('GCM_TAG');const pt=new Uint8Array(ct.length);let cv=2;for(let i=0;i<ct.length;i+=16){const cb=new Uint8Array(16);cb.set(nonce);cb[12]=(cv>>>24)&0xff;cb[13]=(cv>>>16)&0xff;cb[14]=(cv>>>8)&0xff;cb[15]=cv&0xff;const ec=_aesEB(rk,cb);const n=Math.min(16,ct.length-i);for(let j=0;j<n;j++)pt[i+j]=ct[i+j]^ec[j];cv++;}_s.rx=f.counter;return new TextDecoder().decode(pt);}
let _reloading=false;
function handleNetErr(){if(_reloading)return;_reloading=true;stopHB();_s.ek=null;_s.mk=null;document.getElementById('loginScreen').classList.add('active');showToast('Reconnect to AP mode required','error');setTimeout(()=>location.reload(),2000);setTimeout(()=>{_reloading=false;},8000);}
async function apiPost(path,body,opt={}){
  const url=(opt.realPath?path:(_s.paths[path.replace('/api/vault/','')]||path));
  const h={'Content-Type':'application/json','X-CSRF-Token':_s.csrf||'','X-Req-UUID':_s.cid||'','X-Security-Level':'true'};
  for(const fh of(_s.fh||[]))h[fh]=randomHex(8);
  if(opt.tunnel)h['X-Real-Method']=xorEnc(opt.tunnel,_s.cid);
  const bodyStr=body&&_s.ek?encryptBody(JSON.stringify(body)):(body?JSON.stringify(body):'{}');
  let resp;try{const ctrl=new AbortController();const tid=setTimeout(()=>ctrl.abort(),10000);resp=await fetch(url,{method:'POST',headers:h,body:bodyStr,credentials:'include',signal:ctrl.signal});clearTimeout(tid);}catch(e){handleNetErr();throw new Error(e.name==='AbortError'?'Timeout':'Network');}
  if(resp.status===401||resp.status===403){const t=await resp.text().catch(()=> '');if(t.includes('decrypt_failed')||t.includes('unauthorized')||t.includes('csrf_mismatch')){handleNetErr();throw new Error('Session expired');}}
  const text=await resp.text();if(!resp.ok){let err;try{err=JSON.parse(text);}catch(e){err={error:text};}throw new Error(err.error||('HTTP '+resp.status));}
  if(text.startsWith('{')&&text.includes('"ct"')&&text.includes('"tag"')){try{return JSON.parse(await decryptBody(text));}catch(e){handleNetErr();throw new Error('Decrypt');}}
  return text?JSON.parse(text):{};
}
function xorEnc(m,cid){let k='MT_ESP32_'+cid+'_METHOD_KEY';if(k.length>32)k=k.substring(0,32);while(k.length<32)k+='X';let o='';const HC='0123456789abcdef';for(let i=0;i<m.length;i++){const x=m.charCodeAt(i)^k.charCodeAt(i%k.length);o+=HC[(x>>4)&0x0F]+HC[x&0x0F];}return o;}
function toggleSidebar(){document.getElementById('sidebar').classList.toggle('open');document.getElementById('overlay').classList.toggle('active');}
function closeSidebar(){document.getElementById('sidebar').classList.remove('open');document.getElementById('overlay').classList.remove('active');}
function setFilter(f){
  _filter=f;
  document.querySelectorAll('.type-item').forEach(el=>el.classList.remove('active'));
  const el=document.querySelector('[data-filter="'+f+'"]');if(el)el.classList.add('active');
  const names={255:'All Items',256:'Favorites',0:'Login',1:'Card',2:'Identity',3:'Note',254:'Trash'};
  document.getElementById('headerTitle').textContent=names[f]||'All Items';
  closeSidebar();renderVault();
}
async function doLogin(){
  const code=document.getElementById('codeInput').value.trim();
  if(code.length!==6||!/^\d{6}$/.test(code)){showLoginErr('Code must be 6 digits');return;}
  const btn=document.getElementById('loginBtn');btn.disabled=true;
  document.getElementById('loginError').textContent='';
  try{
    _s.cid=safeLS('sv_cid')||randomHex(16);safeLS('sv_cid',_s.cid);
    const s1=await apiPost('/api/secure/hello',{clientId:_s.cid},{realPath:true});
    if(!s1.ok||s1.step!==1)throw new Error(s1.error||'Challenge failed');
    const nb=new Uint8Array(b64ToBuf(s1.serverNonce));const cb=new TextEncoder().encode(code);
    const pb=hmacSha256(cb,nb);const cp=Array.from(pb).map(b=>b.toString(16).padStart(2,'0')).join('');
    const s2=await apiPost('/api/secure/hello',{clientId:_s.cid,serverNonce:s1.serverNonce,codeProof:cp},{realPath:true});
    if(!s2.ok||s2.step!==2)throw new Error(s2.error||'Login failed');
    _s.csrf=s2.csrfToken;_s.fh=typeof s2.fakeHeaders==='string'?JSON.parse(s2.fakeHeaders):(s2.fakeHeaders||[]);_s.paths=typeof s2.obfuscatedPaths==='string'?JSON.parse(s2.obfuscatedPaths):(s2.obfuscatedPaths||{});
    deriveKeys(code,s1.serverNonce);
    document.getElementById('loginScreen').classList.remove('active');
    await refreshList();
  }catch(e){showLoginErr(e.message);}finally{btn.disabled=false;}
}
function showLoginErr(msg){document.getElementById('loginError').textContent=msg;}
async function doLogout(){stopHB();_s={csrf:null,cid:_s.cid,ek:null,mk:null,rx:0,tx:1,paths:{},fh:[]};location.reload();}
async function refreshList(){try{const r=await apiPost('/api/vault/list',{});if(!r.ok)throw new Error(r.error);_entries=r.entries||[];updateCounts();renderVault();}catch(e){showToast(e.message,'error');}}
function updateCounts(){
  const c={255:0,256:0,0:0,1:0,2:0,3:0,254:0};
  for(const e of _entries){
    if(e.deleted){c[254]++;continue;}
    c[255]++;if(e.favorite)c[256]++;if(e.type==='login')c[0]++;else if(e.type==='card')c[1]++;else if(e.type==='identity')c[2]++;else if(e.type==='note')c[3]++;
  }
  for(const k in c){const el=document.getElementById('count-'+k);if(el)el.textContent=c[k];}
}
function getFiltered(){
  const q=(document.getElementById('searchBox').value||'').toLowerCase();
  let list=_entries.filter(e=>{
    if(_filter===254)return e.deleted;
    if(e.deleted)return false;
    if(_filter===256)return e.favorite;
    if(_filter===255)return true;
    if(_filter===0)return e.type==='login';
    if(_filter===1)return e.type==='card';
    if(_filter===2)return e.type==='identity';
    if(_filter===3)return e.type==='note';
    return true;
  });
  if(q)list=list.filter(e=>(e.site&&e.site.toLowerCase().includes(q))||(e.user&&e.user.toLowerCase().includes(q))||(e.url&&e.url.toLowerCase().includes(q))||(e.notes&&e.notes.toLowerCase().includes(q)));
  // Favorites first
  list.sort((a,b)=>(b.favorite?1:0)-(a.favorite?1:0));
  return list;
}
function renderVault(){
  const list=document.getElementById('entryList');
  const filtered=getFiltered();
  list.innerHTML='';
  if(filtered.length===0){list.innerHTML='<div class="empty">No entries found</div>';return;}
  const typeIcons={login:'\u{1F310}',card:'\u{1F4B3}',identity:'\u{1F9D1}',note:'\u{1F4DD}'};
  for(const e of filtered){
    const ri=_entries.indexOf(e);
    const d=document.createElement('div');
    d.className='entry-card'+(_selIdx===ri?' selected':'');
    d.onclick=()=>selectEntry(ri);
    const ic=e.type||'login';
    d.innerHTML='<div class="type-icon '+ic+'">'+(typeIcons[ic]||'\u{1F310}')+'</div><div class="info"><div class="name">'+esc(e.site)+'</div><div class="sub">'+esc(e.user||e.cardholder||'')+'</div></div>'+(e.favorite?'<span class="fav-star">\u2605</span>':'')+'<span class="menu-btn" onclick="event.stopPropagation();selectEntry('+ri+');openDeleteModal('+ri+')">\u22ee</span>';
    list.appendChild(d);
  }
}
function filterEntries(){renderVault();}
function selectEntry(idx){
  _selIdx=idx;const e=_entries[idx];if(!e)return;
  if(_isDesktop){renderDetail(e);renderVault();}
  else{openEditModal(idx);}
}
function renderDetail(e){
  const dc=document.getElementById('detailContent');
  let f='';
  if(e.type==='login'){f+=df('Username',e.user)+df('Password',e.pass,true)+df('URL',e.url)+df('TOTP',e.totp,true);}
  else if(e.type==='card'){f+=df('Cardholder',e.cardholder)+df('Number',e.cardNumber,true)+df('Exp',e.exp)+df('CVV',e.cvv,true);}
  else if(e.type==='identity'){f+=df('First',e.firstName)+df('Last',e.lastName)+df('Email',e.email)+df('Phone',e.phone)+df('Address',e.address)+df('SSN',e.ssn,true)+df('Passport',e.passport,true)+df('License',e.license,true);}
  f+=df('Notes',e.notes)+df('Folder',e.folder);
  dc.innerHTML='<div class="detail-header"><h3>'+esc(e.site)+'</h3></div>'+f+'<div class="detail-actions"><button onclick="openEditModal(_selIdx)">Edit</button><button class="danger" onclick="openDeleteModal(_selIdx)">Delete</button></div>';
  dc.querySelectorAll('.detail-field-value.secret').forEach(el=>{el.onclick=()=>{if(el.dataset.r==='1'){el.textContent='\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';el.dataset.r='0';}else{el.textContent=el.dataset.v;el.dataset.r='1';}};el.dataset.v=el.textContent;el.textContent='\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022';el.dataset.r='0';});
}
function df(l,v,s){if(!v)return'';return'<div class="detail-field"><div><div class="detail-field-label">'+l+'</div><div class="detail-field-value'+(s?' secret':'')+'">'+esc(v)+'</div></div></div>';}
function openAddModal(){_editIdx=-1;document.getElementById('modalTitle').textContent='Add Entry';document.getElementById('f_type').value='login';document.getElementById('f_fav').checked=false;clearForm();renderTypeFields();document.getElementById('entryModal').classList.add('active');}
function openEditModal(idx){_editIdx=idx;const e=_entries[idx];if(!e)return;document.getElementById('modalTitle').textContent='Edit Entry';document.getElementById('f_type').value=e.type;document.getElementById('f_fav').checked=!!e.favorite;setF('f_site',e.site);setF('f_folder',e.folder);setF('f_notes',e.notes);renderTypeFields();if(e.type==='login'){setF('f_user',e.user);setF('f_pass',e.pass);setF('f_url',e.url);setF('f_totp',e.totp);}else if(e.type==='card'){setF('f_cardholder',e.cardholder);setF('f_cardNumber',e.cardNumber);setF('f_exp',e.exp);setF('f_cvv',e.cvv);}else if(e.type==='identity'){setF('f_firstName',e.firstName);setF('f_lastName',e.lastName);setF('f_email',e.email);setF('f_phone',e.phone);setF('f_address',e.address);setF('f_ssn',e.ssn);setF('f_passport',e.passport);setF('f_license',e.license);}document.getElementById('entryModal').classList.add('active');}
function openDeleteModal(idx){_delIdx=idx;const e=_entries[idx];document.getElementById('deleteMsg').textContent='Delete "'+(e?e.site:'this entry')+'"?';document.getElementById('deleteModal').classList.add('active');}
function closeModal(){document.getElementById('entryModal').classList.remove('active');}
function closeDeleteModal(){document.getElementById('deleteModal').classList.remove('active');}
function renderTypeFields(){const t=document.getElementById('f_type').value;const c=document.getElementById('typeFields');let h='';if(t==='login')h='<div class="row"><label>Username</label><input id="f_user" type="text"></div><div class="row"><label>Password</label><input id="f_pass" type="text" autocomplete="off"></div><div class="row"><label>URL</label><input id="f_url" type="text"></div><div class="row"><label>TOTP</label><input id="f_totp" type="text" autocomplete="off"></div>';else if(t==='card')h='<div class="row"><label>Cardholder</label><input id="f_cardholder" type="text"></div><div class="row"><label>Number</label><input id="f_cardNumber" type="text" autocomplete="off"></div><div class="row split"><div><label>Exp</label><input id="f_exp" type="text" placeholder="MM/YY" autocomplete="off"></div><div><label>CVV</label><input id="f_cvv" type="text" autocomplete="off"></div></div>';else if(t==='identity')h='<div class="row split"><div><label>First</label><input id="f_firstName" type="text"></div><div><label>Last</label><input id="f_lastName" type="text"></div></div><div class="row"><label>Email</label><input id="f_email" type="email"></div><div class="row"><label>Phone</label><input id="f_phone" type="tel"></div><div class="row"><label>Address</label><input id="f_address" type="text"></div><div class="row split"><div><label>SSN</label><input id="f_ssn" type="text" autocomplete="off"></div><div><label>Passport</label><input id="f_passport" type="text" autocomplete="off"></div></div><div class="row"><label>License</label><input id="f_license" type="text" autocomplete="off"></div>';c.innerHTML=h;}
function getF(id){const el=document.getElementById(id);return el?el.value:'';}
function setF(id,v){const el=document.getElementById(id);if(el)el.value=v||'';}
function clearForm(){['f_site','f_folder','f_notes','f_user','f_pass','f_url','f_totp','f_cardholder','f_cardNumber','f_exp','f_cvv','f_firstName','f_lastName','f_email','f_phone','f_address','f_ssn','f_passport','f_license'].forEach(id=>setF(id,''));}
async function saveEntry(){
  const btn=document.getElementById('saveBtn');if(btn.disabled)return;btn.disabled=true;
  const type=document.getElementById('f_type').value;
  const entry={type,site:getF('f_site'),folder:getF('f_folder'),notes:getF('f_notes'),favorite:document.getElementById('f_fav').checked};
  if(type==='login'){entry.user=getF('f_user');entry.pass=getF('f_pass');entry.url=getF('f_url');entry.totp=getF('f_totp');}
  else if(type==='card'){entry.cardholder=getF('f_cardholder');entry.cardNumber=getF('f_cardNumber');entry.exp=getF('f_exp');entry.cvv=getF('f_cvv');}
  else if(type==='identity'){entry.firstName=getF('f_firstName');entry.lastName=getF('f_lastName');entry.email=getF('f_email');entry.phone=getF('f_phone');entry.address=getF('f_address');entry.ssn=getF('f_ssn');entry.passport=getF('f_passport');entry.license=getF('f_license');}
  if(!entry.site){showToast('Site is required','error');btn.disabled=false;return;}
  try{
    if(_editIdx<0){const r=await apiPost('/api/vault/add',entry);if(!r.ok)throw new Error(r.error);showToast('Added','success');}
    else{entry.index=_entries[_editIdx].index;const r=await apiPost('/api/tunnel',{endpoint:'/api/vault/edit',data:entry},{tunnel:'PUT'});if(!r.ok)throw new Error(r.error);showToast('Saved','success');}
    closeModal();await refreshList();if(_isDesktop&&_editIdx>=0&&_selIdx===_editIdx)renderDetail(_entries[_editIdx]);
  }catch(e){showToast(e.message,'error');}finally{btn.disabled=false;}
}
async function confirmDelete(){
  if(_delIdx<0)return;const btn=document.getElementById('delBtn');if(btn&&btn.disabled)return;if(btn)btn.disabled=true;
  try{const r=await apiPost('/api/tunnel',{endpoint:'/api/vault/delete',data:{index:_entries[_delIdx].index}},{tunnel:'DELETE'});if(!r.ok)throw new Error(r.error);showToast('Deleted','success');closeDeleteModal();if(_selIdx===_delIdx){_selIdx=-1;document.getElementById('detailContent').innerHTML='<div class="detail-empty">Select an entry</div>';}await refreshList();}
  catch(e){showToast(e.message,'error');}finally{if(btn)btn.disabled=false;}
}
function showToast(msg,kind){const t=document.getElementById('toast');t.textContent=msg;t.className='toast show '+(kind||'');setTimeout(()=>t.classList.remove('show'),2500);}
function esc(s){if(!s)return'';return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
document.getElementById('codeInput').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
window.addEventListener('pageshow',e=>{if(e.persisted&&_s.ek)handleNetErr();});
let _lastVis=Date.now();document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'){if(Date.now()-_lastVis>30000&&_s.ek)heartbeat();}else{_lastVis=Date.now();}});
let _hbFail=0,_hbTimer=null;function startHB(){if(_hbTimer)clearInterval(_hbTimer);_hbTimer=setInterval(heartbeat,15000);}function stopHB(){if(_hbTimer){clearInterval(_hbTimer);_hbTimer=null;}}
async function heartbeat(){if(!_s.ek)return;try{const r=await fetch('/',{method:'GET',cache:'no-store'});if(r.ok)_hbFail=0;else _hbFail++;}catch(e){_hbFail++;if(_hbFail>=2)handleNetErr();}}
const _ol=doLogin;doLogin=async function(){await _ol();if(_s.ek)startHB();};
const _olog=doLogout;doLogout=async function(){stopHB();await _olog();};
</script>
</body>
</html>)HTML";

static const size_t PORTAL_HTML_LEN = sizeof(PORTAL_HTML) - 1;
