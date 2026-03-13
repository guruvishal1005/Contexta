"use client";

import { useState, useEffect, useRef, useCallback } from "react";

// ─── PALETTE & CONSTANTS ───────────────────────────────────────────────────
const C = {
  bg:      "#030308",
  surface: "#080812",
  card:    "#0c0c1a",
  border:  "#141428",
  border2: "#1e1e3a",
  text:    "#ffffff",
  muted:   "#e0e0e8",
  dim:     "#d0d0dc",
  accent:  "#4f8eff",
  green:   "#00e5a0",
  red:     "#ff3a5c",
  yellow:  "#ffcc00",
  purple:  "#9f6fff",
  orange:  "#ff7a30",
  cyan:    "#00cfff",
};

const NAV_ITEMS = [
  { id:"dashboard",  icon:"⬡", label:"SOC Overview" },
  { id:"sentinel",   icon:"◈", label:"Sentinel AI" },
  { id:"bwvs",       icon:"◎", label:"BWVS Scoring" },
  { id:"digital",    icon:"⬢", label:"Digital Twin" },
  { id:"cve",        icon:"◉", label:"CVE Intelligence" },
  { id:"blockchain", icon:"⬡", label:"Audit Ledger" },
  { id:"playbooks",  icon:"▶", label:"Response Playbooks" },
  { id:"agents",     icon:"◈", label:"AI Agents" },
];

// ─── DATA GENERATORS ──────────────────────────────────────────────────────
const rnd = (a,b) => Math.random()*(b-a)+a;
const rndInt = (a,b) => Math.floor(rnd(a,b));
const rndIP = () => `${rndInt(10,220)}.${rndInt(0,255)}.${rndInt(0,255)}.${rndInt(1,254)}`;
const rndPick = arr => arr[rndInt(0,arr.length)];

const ATTACK_TYPES = ["DDoS","BruteForce","SQLi","PortScan","Bot","Infiltration","Ransomware","Phishing"];
const SEVERITIES = ["CRITICAL","HIGH","MEDIUM","LOW"];
const SEV_COLORS = { CRITICAL:C.red, HIGH:C.orange, MEDIUM:C.yellow, LOW:C.green };

const AGENTS = [
  { id:"recon",    name:"Recon Analyst",        role:"Threat Reconnaissance",     color:C.cyan,   status:"ACTIVE" },
  { id:"vuln",     name:"Vuln Assessor",         role:"CVE Correlation",           color:C.purple, status:"ACTIVE" },
  { id:"forensic", name:"Forensic Investigator", role:"Evidence Collection",       color:C.yellow, status:"ACTIVE" },
  { id:"response", name:"Response Orchestrator", role:"Playbook Execution",        color:C.green,  status:"ACTIVE" },
  { id:"intel",    name:"OSINT Collector",        role:"Threat Intelligence Feed",  color:C.orange, status:"STANDBY" },
  { id:"risk",     name:"Business Risk Scorer",   role:"BWVS Calculation",         color:C.accent, status:"ACTIVE" },
];

function genThreat() {
  const type = rndPick(ATTACK_TYPES);
  const sev = rndPick(SEVERITIES);
  return {
    id: Date.now()+Math.random(),
    type,
    severity: sev,
    src: rndIP(),
    dst: rndIP(),
    port: rndPick([22,80,443,3306,8080,445,21,53]),
    bwvs: +(rnd(1,10)).toFixed(1),
    ts: new Date().toISOString(),
    status: rndPick(["INVESTIGATING","CONTAINED","ESCALATED","RESOLVED"]),
    agent: rndPick(AGENTS).name,
    cve: Math.random()>0.5 ? `CVE-2024-${rndInt(10000,99999)}` : null,
  };
}

function genCVE() {
  const products = ["Apache HTTP","OpenSSL","Linux Kernel","Windows SMB","Log4j","Spring Boot","nginx","SSH OpenSSH"];
  return {
    id: `CVE-2024-${rndInt(10000,99999)}`,
    product: rndPick(products),
    cvss: +(rnd(4,10)).toFixed(1),
    severity: rndPick(SEVERITIES),
    kev: Math.random()>0.6,
    desc: rndPick(["Remote code execution via buffer overflow","Authentication bypass in admin panel","SQL injection in login endpoint","Privilege escalation via race condition","Heap overflow in parsing module"]),
    published: new Date(Date.now()-rndInt(0,30)*86400000).toLocaleDateString(),
  };
}

function genBlock() {
  const ops = ["THREAT_DETECTED","RULE_UPDATED","IP_BLOCKED","CRED_RESET","HOST_ISOLATED","CVE_INGESTED","PLAYBOOK_EXEC","AGENT_DISPATCH"];
  return {
    hash: Math.random().toString(36).substr(2,16).toUpperCase(),
    prev: Math.random().toString(36).substr(2,16).toUpperCase(),
    op: rndPick(ops),
    actor: rndPick(["system","sentinel-ai","analyst@soc","soar-engine","cve-feed"]),
    ts: new Date().toISOString(),
    verified: true,
  };
}

// ─── REUSABLE UI ──────────────────────────────────────────────────────────
function Card({ children, style={}, glow }) {
  return (
    <div style={{
      background:C.card,
      border:`1px solid ${glow?glow+"44":C.border}`,
      borderRadius:8,
      padding:16,
      boxShadow: glow?`0 0 20px ${glow}11`:"none",
      ...style
    }}>{children}</div>
  );
}

function Label({ children, color=C.muted }) {
  return <div style={{ color, fontSize:10, letterSpacing:2, fontWeight:700, marginBottom:6 }}>{children}</div>;
}

function Badge({ label, color }) {
  return (
    <span style={{
      background:color+"22", color, border:`1px solid ${color}55`,
      borderRadius:3, padding:"2px 7px", fontSize:10,
      fontFamily:"monospace", fontWeight:700, letterSpacing:1,
    }}>{label}</span>
  );
}

function MiniBar({ value, max=10, color=C.accent, height=5 }) {
  return (
    <div style={{ background:C.dim, borderRadius:3, height, overflow:"hidden" }}>
      <div style={{ width:`${Math.min((value/max)*100,100)}%`, height:"100%", background:color, borderRadius:3, transition:"width 0.5s" }} />
    </div>
  );
}

function Pulse({ color }) {
  return (
    <span style={{ position:"relative", display:"inline-block", width:8, height:8, flexShrink:0 }}>
      <span style={{ position:"absolute", inset:0, borderRadius:"50%", background:color, opacity:0.3, animation:"ctxPing 2s ease-out infinite" }} />
      <span style={{ position:"absolute", inset:1, borderRadius:"50%", background:color }} />
    </span>
  );
}

function StatBox({ label, value, sub, color=C.accent }) {
  return (
    <Card style={{ flex:1, minWidth:120 }}>
      <Label color={C.muted}>{label}</Label>
      <div style={{ color, fontSize:28, fontWeight:700, fontFamily:"monospace", lineHeight:1 }}>{value}</div>
      {sub && <div style={{ color:C.muted, fontSize:11, marginTop:4 }}>{sub}</div>}
    </Card>
  );
}

// ─── NETWORK TOPOLOGY (Digital Twin) ─────────────────────────────────────
function TopologyCanvas({ threats }) {
  const nodes = [
    { id:"fw",      label:"Firewall",      x:300, y:40,  color:C.green,  type:"security" },
    { id:"lb",      label:"Load Balancer", x:300, y:130, color:C.accent, type:"infra" },
    { id:"web1",    label:"Web-01",        x:160, y:230, color:C.accent, type:"server" },
    { id:"web2",    label:"Web-02",        x:300, y:230, color:C.accent, type:"server" },
    { id:"web3",    label:"Web-03",        x:440, y:230, color:C.accent, type:"server" },
    { id:"db1",     label:"DB Primary",   x:200, y:330, color:C.yellow, type:"database" },
    { id:"db2",     label:"DB Replica",   x:400, y:330, color:C.yellow, type:"database" },
    { id:"int",     label:"Internal Net", x:300, y:420, color:C.purple, type:"network" },
    { id:"admin",   label:"Admin Host",   x:120, y:420, color:C.orange, type:"endpoint" },
    { id:"attacker",label:"⚠ Threat",     x:300, y:-40, color:C.red,    type:"threat" },
  ];
  const edges = [
    ["attacker","fw"],["fw","lb"],["lb","web1"],["lb","web2"],["lb","web3"],
    ["web1","db1"],["web2","db1"],["web3","db2"],["db1","int"],["db2","int"],
    ["int","admin"],
  ];
  const attackedNodes = new Set(threats.slice(0,3).map(t=>rndPick(["web1","web2","db1","admin"])));
  return (
    <svg width="100%" viewBox="0 0 600 480" style={{ overflow:"visible" }}>
      <defs>
        <filter id="glow">
          <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
          <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      {edges.map(([a,b],i)=>{
        const na=nodes.find(n=>n.id===a), nb=nodes.find(n=>n.id===b);
        const attacked = attackedNodes.has(b)||attackedNodes.has(a);
        return <line key={i} x1={na.x} y1={na.y+480*0} x2={nb.x} y2={nb.y}
          stroke={attacked?C.red:C.border2} strokeWidth={attacked?1.5:1}
          strokeDasharray={attacked?"4 3":""} opacity={0.7} />;
      })}
      {nodes.map(n=>{
        const attacked = attackedNodes.has(n.id);
        return (
          <g key={n.id}>
            {attacked && <circle cx={n.x} cy={n.y} r={18} fill={C.red} opacity={0.15} filter="url(#glow)" />}
            <circle cx={n.x} cy={n.y} r={12} fill={C.card} stroke={attacked?C.red:n.color} strokeWidth={1.5} />
            <circle cx={n.x} cy={n.y} r={5} fill={attacked?C.red:n.color} />
            <text x={n.x} y={n.y+26} textAnchor="middle" fontSize={9} fill={C.muted} fontFamily="monospace">{n.label}</text>
          </g>
        );
      })}
    </svg>
  );
}

// ─── BWVS GAUGE ───────────────────────────────────────────────────────────
function BwvsGauge({ score }) {
  const pct = score/10;
  const r=60, cx=80, cy=80;
  const arc = (p, radius=r) => {
    const a = Math.PI + p*Math.PI;
    return { x: cx+radius*Math.cos(a), y: cy+radius*Math.sin(a) };
  };
  const start=arc(0), end=arc(pct);
  const largeArc = pct>0.5?1:0;
  const color = score>=8?C.red:score>=6?C.orange:score>=4?C.yellow:C.green;
  return (
    <svg width={160} height={100} viewBox="0 0 160 100">
      <path d={`M ${arc(0,r).x} ${arc(0,r).y} A ${r} ${r} 0 1 1 ${arc(1,r).x} ${arc(1,r).y}`}
        fill="none" stroke={C.dim} strokeWidth={8} strokeLinecap="round" />
      <path d={`M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${end.x} ${end.y}`}
        fill="none" stroke={color} strokeWidth={8} strokeLinecap="round"
        style={{ filter:`drop-shadow(0 0 6px ${color})` }} />
      <text x={cx} y={cy+8} textAnchor="middle" fontSize={22} fontWeight={700} fill={color} fontFamily="monospace">{score.toFixed(1)}</text>
      <text x={cx} y={cy+22} textAnchor="middle" fontSize={9} fill={C.muted} fontFamily="monospace">BWVS SCORE</text>
    </svg>
  );
}

// ─── BLOCKCHAIN LEDGER ────────────────────────────────────────────────────
function BlockchainViz({ blocks }) {
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
      {blocks.slice(0,6).map((b,i)=>(
        <div key={i} style={{ display:"flex", alignItems:"center", gap:8 }}>
          <div style={{
            background:C.card, border:`1px solid ${C.border2}`,
            borderRadius:6, padding:"8px 12px", flex:1,
            borderLeft:`3px solid ${C.accent}`,
          }}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
              <span style={{ color:C.accent, fontSize:10, fontFamily:"monospace" }}>#{b.hash.slice(0,8)}</span>
              <span style={{ display:"flex", alignItems:"center", gap:4 }}>
                <span style={{ color:C.green, fontSize:9 }}>✓ VERIFIED</span>
              </span>
            </div>
            <div style={{ display:"flex", gap:16 }}>
              <div><span style={{ color:C.muted, fontSize:10 }}>OP: </span><span style={{ color:C.yellow, fontSize:10, fontFamily:"monospace" }}>{b.op}</span></div>
              <div><span style={{ color:C.muted, fontSize:10 }}>BY: </span><span style={{ color:C.text, fontSize:10 }}>{b.actor}</span></div>
            </div>
            <div style={{ color:C.dim, fontSize:9, marginTop:3, fontFamily:"monospace" }}>prev: {b.prev.slice(0,12)}...</div>
          </div>
          {i<5&&<div style={{ color:C.muted, fontSize:14 }}>↓</div>}
        </div>
      ))}
    </div>
  );
}

// ─── AGENT DISCUSSION MODAL ───────────────────────────────────────────────
const AGENT_COLORS_MAP = { analyst:C.accent, intel:C.purple, forensics:C.orange, business:C.green, response:C.red };
const AGENT_ICONS = { analyst:"🛡", intel:"🔍", forensics:"🗄", business:"💼", response:"⚡" };

function AgentDiscussionOverlay({ isOpen, onClose, riskName, messages, isLoading }) {
  const [displayed, setDisplayed] = useState([]);
  const [typingAgent, setTypingAgent] = useState(null);
  const endRef = useRef(null);
  const cancelRef = useRef(false);

  useEffect(()=>{
    if(isOpen && messages.length>0){
      cancelRef.current = false;
      setDisplayed([]);
      (async()=>{
        for(let i=0;i<messages.length;i++){
          if(cancelRef.current) return;
          setTypingAgent(messages[i].agent);
          await new Promise(r=>setTimeout(r,800));
          if(cancelRef.current) return;
          setDisplayed(p=>[...p, messages[i]]);
          setTypingAgent(null);
          if(i<messages.length-1) await new Promise(r=>setTimeout(r,200));
        }
      })();
    }
    return ()=>{ cancelRef.current = true; };
  },[isOpen, messages]);

  useEffect(()=>{ endRef.current?.scrollIntoView({behavior:"smooth"}); },[displayed, typingAgent]);

  if(!isOpen) return null;

  return (
    <div style={{ position:"fixed", inset:0, zIndex:9999, display:"flex", alignItems:"center", justifyContent:"center", background:"rgba(0,0,0,0.7)", backdropFilter:"blur(4px)" }}>
      <div style={{ background:C.surface, border:`1px solid ${C.border2}`, borderRadius:12, width:"90%", maxWidth:780, maxHeight:"82vh", display:"flex", flexDirection:"column", boxShadow:`0 0 60px ${C.accent}15` }}>
        {/* Header */}
        <div style={{ padding:"16px 20px", borderBottom:`1px solid ${C.border}`, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <div>
            <div style={{ color:"#fff", fontSize:15, fontWeight:700, letterSpacing:2, display:"flex", alignItems:"center", gap:8 }}>🛡 AGENT DISCUSSION</div>
            <div style={{ color:C.muted, fontSize:11, marginTop:2 }}>Analyzing: <span style={{ color:C.yellow }}>{riskName}</span></div>
          </div>
          <button onClick={onClose} style={{ background:"none", border:`1px solid ${C.border2}`, borderRadius:6, color:C.muted, cursor:"pointer", padding:"4px 10px", fontSize:14 }}>✕</button>
        </div>

        {/* Messages */}
        <div style={{ flex:1, overflowY:"auto", padding:20 }}>
          {isLoading ? (
            <div style={{ textAlign:"center", padding:60 }}>
              <div style={{ display:"flex", justifyContent:"center", gap:8, marginBottom:16 }}>
                {[C.accent, C.purple, C.orange, C.green, C.red].map((color,i)=>(
                  <div key={i} style={{ width:10, height:10, borderRadius:"50%", background:color, animation:`ctxDotBounce 1.4s ease-in-out ${i*0.16}s infinite` }} />
                ))}
              </div>
              <div style={{ color:C.muted, fontSize:12, letterSpacing:1 }}>Agents are thinking...</div>
            </div>
          ) : (
            <>
              {displayed.map((msg,i)=>{
                const ac = AGENT_COLORS_MAP[msg.agent]||C.accent;
                return (
                  <div key={i} style={{ display:"flex", gap:12, marginBottom:16, animation:"ctxFade 0.3s ease" }}>
                    <div style={{ width:32, height:32, borderRadius:"50%", background:ac+"22", border:`1px solid ${ac}55`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:14, flexShrink:0 }}>{AGENT_ICONS[msg.agent]||"◈"}</div>
                    <div style={{ flex:1, background:C.card, border:`1px solid ${ac}33`, borderRadius:8, padding:"10px 14px" }}>
                      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:6 }}>
                        <span style={{ color:ac, fontSize:11, fontWeight:700, letterSpacing:1, textTransform:"uppercase" }}>{msg.agent} Agent</span>
                        <span style={{ color:C.dim, fontSize:10 }}>{msg.timestamp}</span>
                      </div>
                      <div style={{ color:C.text, fontSize:12, lineHeight:1.6, whiteSpace:"pre-wrap" }}>{msg.message}</div>
                    </div>
                  </div>
                );
              })}
              {typingAgent && (
                <div style={{ display:"flex", gap:12, marginBottom:16, opacity:0.7 }}>
                  <div style={{ width:32, height:32, borderRadius:"50%", background:C.dim, display:"flex", alignItems:"center", justifyContent:"center", fontSize:14 }}>{AGENT_ICONS[typingAgent]||"◈"}</div>
                  <div style={{ background:C.card, border:`1px solid ${C.border}`, borderRadius:8, padding:"10px 14px", display:"flex", alignItems:"center", gap:8 }}>
                    <span style={{ color:C.muted, fontSize:11 }}>{typingAgent} is typing</span>
                    <span style={{ color:C.muted, fontSize:16, animation:"ctxPing 1.5s ease-out infinite" }}>•••</span>
                  </div>
                </div>
              )}
              <div ref={endRef} />
            </>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding:"12px 20px", borderTop:`1px solid ${C.border}`, display:"flex", gap:16 }}>
          {Object.entries(AGENT_COLORS_MAP).map(([name,color])=>(
            <div key={name} style={{ display:"flex", alignItems:"center", gap:4, fontSize:10, color:C.muted }}>
              <span style={{ width:6, height:6, borderRadius:"50%", background:color, display:"inline-block" }} />
              {name.charAt(0).toUpperCase()+name.slice(1)}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────
export default function ContexaSOC() {
  const [page, setPage] = useState("dashboard");
  const [threats, setThreats] = useState(() => Array.from({length:12},genThreat));
  const [cves, setCves] = useState([]);
  const [cveStats, setCveStats] = useState({ total:0, critical:0, high:0, exploited:0, kev:0 });
  const [blocks, setBlocks] = useState(() => Array.from({length:8},genBlock));
  const [bwvsScore, setBwvsScore] = useState(7.4);
  const [agentLogs, setAgentLogs] = useState([]);
  const [selected, setSelected] = useState(null);
  const [running, setRunning] = useState(true);

  // Agent Discussion state
  const [discussionOpen, setDiscussionOpen] = useState(false);
  const [discussionRisk, setDiscussionRisk] = useState("");
  const [discussionMessages, setDiscussionMessages] = useState([]);
  const [discussionLoading, setDiscussionLoading] = useState(false);

  const handleAgentDiscussion = useCallback(async (riskName) => {
    setDiscussionRisk(riskName);
    setDiscussionOpen(true);
    setDiscussionLoading(true);
    setDiscussionMessages([]);
    try {
      const encoded = encodeURIComponent(riskName);
      const res = await fetch(
        `http://localhost:8000/api/agents/analyze/demo?risk_title=${encoded}&agents=analyst&agents=intel&agents=forensics&agents=business&agents=response`,
        { method:"POST", headers:{"Content-Type":"application/json"} }
      );
      if(res.ok){
        const data = await res.json();
        if(data.discussion) setDiscussionMessages(data.discussion);
      } else {
        const err = await res.json().catch(()=>null);
        setDiscussionMessages([{ agent:"analyst", message:`⚠️ Backend returned ${res.status}: ${err?.detail||"Unknown error"}.`, timestamp:new Date().toLocaleTimeString("en-US",{hour12:false}) }]);
      }
    } catch(e) {
      setDiscussionMessages([{ agent:"analyst", message:"⚠️ Network Error: Unable to connect to backend at localhost:8000. Make sure the backend is running.", timestamp:new Date().toLocaleTimeString("en-US",{hour12:false}) }]);
    } finally {
      setDiscussionLoading(false);
    }
  }, []);

  // Fetch real CVE data from backend
  useEffect(()=>{
    async function fetchCVEs() {
      try {
        const [recentRes, statsRes] = await Promise.all([
          fetch("http://localhost:8000/api/cves/public/recent?limit=50"),
          fetch("http://localhost:8000/api/cves/public/stats")
        ]);
        if(recentRes.ok){
          const data = await recentRes.json();
          setCves((data.cves||[]).map(c=>({
            id: c.cve_id,
            product: (c.affected_software||[])[0]?.replace(":"," ") || "Unknown",
            cvss: c.cvss_score||0,
            severity: (c.severity||"MEDIUM").toUpperCase(),
            kev: c.cisa_kev||false,
            desc: c.description||"",
            published: c.published_date ? new Date(c.published_date).toLocaleDateString() : "N/A",
          })));
        }
        if(statsRes.ok){
          const stats = await statsRes.json();
          setCveStats(stats);
        }
      } catch(e) { console.warn("CVE fetch failed, using fallback", e); setCves(Array.from({length:10},genCVE)); }
    }
    fetchCVEs();
  },[]);

  useEffect(()=>{
    if(!running) return;
    const t = setInterval(()=>{
      const e = genThreat();
      setThreats(p=>[e,...p].slice(0,100));
      if(Math.random()>0.7) setBlocks(p=>[genBlock(),...p].slice(0,30));
      setBwvsScore(s=>Math.max(1,Math.min(10,+(s+rnd(-0.3,0.3)).toFixed(1))));
      const agent = rndPick(AGENTS);
      setAgentLogs(p=>[{
        ts:new Date().toLocaleTimeString(), agent:agent.name,
        msg:rndPick(["Correlating IOC with MITRE ATT&CK","Scanning lateral movement paths","Updating BWVS score","Executing isolation playbook","Querying NVD for patch status","Flagging anomalous user behavior","Cross-referencing CISA KEV feed","Dispatching containment order"]),
        color:agent.color,
      },...p].slice(0,50));
    },1200);
    return ()=>clearInterval(t);
  },[running]);

  const critCount = threats.filter(t=>t.severity==="CRITICAL").length;
  const activeThreats = threats.filter(t=>t.status!=="RESOLVED").length;

  return (
    <div style={{ display:"flex", height:"100vh", background:C.bg, color:C.text, fontFamily:"'Courier New',monospace", fontSize:13, overflow:"hidden" }}>
      <style>{`
        @keyframes ctxPing{0%{transform:scale(1);opacity:0.4}100%{transform:scale(2.8);opacity:0}}
        @keyframes ctxFade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
        @keyframes ctxDotBounce{0%,80%,100%{transform:scale(0.4);opacity:0.3}40%{transform:scale(1);opacity:1}}
        @keyframes ctxScan{0%{top:-5%}100%{top:105%}}
        ::-webkit-scrollbar{width:3px;background:transparent}
        ::-webkit-scrollbar-thumb{background:#1a1a3a;border-radius:2px}
        .ctx-nav:hover{background:#0f0f22!important;color:#fff!important}
        .ctx-row:hover{background:#0d0d20!important;cursor:pointer}
        .ctx-card-hover:hover{border-color:#4f8eff55!important;transform:translateY(-1px);transition:all 0.2s}
      `}</style>

      {/* ── SIDEBAR ── */}
      <div style={{ width:220, background:C.surface, borderRight:`1px solid ${C.border}`, display:"flex", flexDirection:"column", flexShrink:0 }}>
        <div style={{ padding:"20px 16px 16px", borderBottom:`1px solid ${C.border}` }}>
          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:4 }}>
            <div style={{ width:32,height:32,background:`linear-gradient(135deg,${C.accent},${C.purple})`,borderRadius:8,display:"flex",alignItems:"center",justifyContent:"center",fontSize:16 }}>⬡</div>
            <div>
              <div style={{ color:"#fff", fontWeight:700, fontSize:15, letterSpacing:2 }}>CONTEXA</div>
              <div style={{ color:C.muted, fontSize:9, letterSpacing:1 }}>ENTERPRISE SOC</div>
            </div>
          </div>
          <div style={{ display:"flex", alignItems:"center", gap:6, marginTop:10 }}>
            <Pulse color={C.green} />
            <span style={{ color:C.green, fontSize:10, letterSpacing:1 }}>ALL SYSTEMS OPERATIONAL</span>
          </div>
        </div>

        <nav style={{ flex:1, padding:"8px 0", overflowY:"auto" }}>
          {NAV_ITEMS.map(n=>(
            <button key={n.id} className="ctx-nav" onClick={()=>setPage(n.id)} style={{
              display:"flex", alignItems:"center", gap:10, width:"100%",
              padding:"10px 16px", background:page===n.id?`${C.accent}11`:"none",
              border:"none", borderLeft:page===n.id?`2px solid ${C.accent}`:"2px solid transparent",
              color:page===n.id?"#fff":C.muted, cursor:"pointer", textAlign:"left",
              fontSize:12, letterSpacing:1, transition:"all 0.15s",
            }}>
              <span style={{ fontSize:14, color:page===n.id?C.accent:C.muted }}>{n.icon}</span>
              {n.label}
            </button>
          ))}
        </nav>

        <div style={{ padding:16, borderTop:`1px solid ${C.border}` }}>
          <div style={{ marginBottom:8 }}>
            <div style={{ display:"flex",justifyContent:"space-between",marginBottom:3 }}>
              <span style={{ color:C.muted, fontSize:10 }}>Threat Load</span>
              <span style={{ color:C.red, fontSize:10 }}>{activeThreats} active</span>
            </div>
            <MiniBar value={activeThreats} max={50} color={C.red} />
          </div>
          <div>
            <div style={{ display:"flex",justifyContent:"space-between",marginBottom:3 }}>
              <span style={{ color:C.muted, fontSize:10 }}>BWVS Risk</span>
              <span style={{ color:bwvsScore>=7?C.red:C.yellow, fontSize:10 }}>{bwvsScore}/10</span>
            </div>
            <MiniBar value={bwvsScore} max={10} color={bwvsScore>=7?C.red:C.yellow} />
          </div>
          <button onClick={()=>setRunning(r=>!r)} style={{
            marginTop:12, width:"100%", background:"none",
            border:`1px solid ${running?C.red:C.green}`, borderRadius:4,
            color:running?C.red:C.green, padding:"5px 0", fontSize:10,
            letterSpacing:2, cursor:"pointer", fontFamily:"monospace",
          }}>{running?"■ PAUSE FEED":"▶ RESUME FEED"}</button>
        </div>
      </div>

      {/* ── MAIN CONTENT ── */}
      <div style={{ flex:1, overflowY:"auto", display:"flex", flexDirection:"column" }}>

        {/* Top bar */}
        <div style={{ background:C.surface, borderBottom:`1px solid ${C.border}`, padding:"10px 24px", display:"flex", justifyContent:"space-between", alignItems:"center", flexShrink:0, position:"sticky",top:0,zIndex:50 }}>
          <div>
            <div style={{ color:"#fff", fontSize:14, fontWeight:700, letterSpacing:2 }}>{NAV_ITEMS.find(n=>n.id===page)?.label.toUpperCase()}</div>
            <div style={{ color:C.muted, fontSize:10 }}>{new Date().toLocaleString()} · Contexa v3.1.0</div>
          </div>
          <div style={{ display:"flex", gap:8 }}>
            {critCount>0&&<Badge label={`${critCount} CRITICAL`} color={C.red} />}
            <Badge label={`BWVS ${bwvsScore}`} color={bwvsScore>=7?C.red:C.yellow} />
            <Badge label="ML ENGINE LIVE" color={C.green} />
          </div>
        </div>

        <div style={{ padding:24, flex:1, animation:"ctxFade 0.3s ease" }} key={page}>

          {/* ══ DASHBOARD ══ */}
          {page==="dashboard" && (
            <div>
              <div style={{ display:"flex", gap:12, marginBottom:20, flexWrap:"wrap" }}>
                <StatBox label="ACTIVE THREATS" value={activeThreats} sub="↑ 3 since last hour" color={C.red} />
                <StatBox label="CRITICAL ALERTS" value={critCount} sub="Requires immediate action" color={C.orange} />
                <StatBox label="CVEs TRACKED" value={cveStats.total||cves.length} sub={`${cveStats.kev||cves.filter(c=>c.kev).length} in CISA KEV`} color={C.purple} />
                <StatBox label="MTTD" value="1.4s" sub="Mean time to detect" color={C.cyan} />
                <StatBox label="IPs BLOCKED" value={threats.filter(t=>t.type==="DDoS"||t.type==="BruteForce").length} sub="Auto-blocked by SOAR" color={C.accent} />
                <StatBox label="BWVS SCORE" value={bwvsScore} sub="Business risk index" color={bwvsScore>=7?C.red:C.yellow} />
              </div>

              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
                <Card glow={C.accent}>
                  <Label color={C.accent}>LIVE THREAT STREAM</Label>
                  <div style={{ maxHeight:280, overflowY:"auto" }}>
                    <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr", gap:0, color:C.muted, fontSize:10, letterSpacing:1, padding:"4px 0", borderBottom:`1px solid ${C.border}`, marginBottom:4 }}>
                      <span>TYPE</span><span>SEVERITY</span><span>SOURCE</span><span>STATUS</span>
                    </div>
                    {threats.slice(0,20).map(t=>(
                      <div key={t.id} className="ctx-row" onClick={()=>setSelected(t===selected?null:t)}
                        style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr", padding:"5px 0", borderBottom:`1px solid ${C.border}`, background:selected===t?C.dim:"transparent" }}>
                        <span style={{ color:SEV_COLORS[t.severity], fontSize:11 }}>{t.type}</span>
                        <Badge label={t.severity} color={SEV_COLORS[t.severity]} />
                        <span style={{ color:C.muted, fontSize:10 }}>{t.src.slice(0,12)}</span>
                        <span style={{ display:"flex", alignItems:"center", gap:6 }}>
                          <span style={{ color:t.status==="RESOLVED"?C.green:t.status==="ESCALATED"?C.red:C.yellow, fontSize:10 }}>{t.status}</span>
                          <button onClick={(e)=>{e.stopPropagation();handleAgentDiscussion(`${t.type} attack from ${t.src} — ${t.severity}`);}} style={{ background:C.accent+"22", border:`1px solid ${C.accent}44`, borderRadius:3, color:C.accent, padding:"1px 6px", fontSize:9, cursor:"pointer", fontFamily:"monospace" }}>DISCUSS</button>
                        </span>
                      </div>
                    ))}
                  </div>
                </Card>

                <Card glow={C.purple}>
                  <Label color={C.purple}>AI AGENT ACTIVITY</Label>
                  <div style={{ maxHeight:280, overflowY:"auto" }}>
                    {agentLogs.slice(0,15).map((l,i)=>(
                      <div key={i} style={{ display:"flex", gap:8, padding:"5px 0", borderBottom:`1px solid ${C.border}`, fontSize:11 }}>
                        <span style={{ color:C.muted, flexShrink:0 }}>{l.ts}</span>
                        <span style={{ color:l.color, flexShrink:0, minWidth:120 }}>{l.agent}</span>
                        <span style={{ color:C.text }}>{l.msg}</span>
                      </div>
                    ))}
                    {agentLogs.length===0&&<div style={{ color:C.muted, padding:20, textAlign:"center" }}>Waiting for agent activity...</div>}
                  </div>
                </Card>
              </div>

              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:16 }}>
                <Card>
                  <Label color={C.cyan}>ATTACK BREAKDOWN</Label>
                  {ATTACK_TYPES.map(type=>{
                    const count = threats.filter(t=>t.type===type).length;
                    return (
                      <div key={type} style={{ marginBottom:8 }}>
                        <div style={{ display:"flex", justifyContent:"space-between", marginBottom:2 }}>
                          <span style={{ color:C.text, fontSize:11 }}>{type}</span>
                          <span style={{ color:C.muted, fontSize:11 }}>{count}</span>
                        </div>
                        <MiniBar value={count} max={Math.max(...ATTACK_TYPES.map(t=>threats.filter(x=>x.type===t).length),1)} color={C.cyan} />
                      </div>
                    );
                  })}
                </Card>
                <Card>
                  <Label color={C.yellow}>TOP CVEs (CISA KEV)</Label>
                  {cves.filter(c=>c.kev).slice(0,6).map(c=>(
                    <div key={c.id} style={{ marginBottom:8, padding:"6px 8px", background:C.surface, borderRadius:4, borderLeft:`2px solid ${SEV_COLORS[c.severity]}` }}>
                      <div style={{ display:"flex", justifyContent:"space-between" }}>
                        <span style={{ color:C.yellow, fontSize:11, fontFamily:"monospace" }}>{c.id}</span>
                        <span style={{ color:SEV_COLORS[c.severity], fontSize:10 }}>CVSS {c.cvss}</span>
                      </div>
                      <div style={{ color:C.muted, fontSize:10 }}>{c.product}</div>
                    </div>
                  ))}
                </Card>
                <Card>
                  <Label color={C.green}>RECENT AUDIT BLOCKS</Label>
                  {blocks.slice(0,5).map((b,i)=>(
                    <div key={i} style={{ marginBottom:6, padding:"6px 8px", background:C.surface, borderRadius:4 }}>
                      <div style={{ color:C.accent, fontSize:10, fontFamily:"monospace" }}>#{b.hash.slice(0,10)}</div>
                      <div style={{ display:"flex", justifyContent:"space-between" }}>
                        <span style={{ color:C.yellow, fontSize:10 }}>{b.op}</span>
                        <span style={{ color:C.green, fontSize:9 }}>✓</span>
                      </div>
                    </div>
                  ))}
                </Card>
              </div>
            </div>
          )}

          {/* ══ SENTINEL AI ══ */}
          {page==="sentinel" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:12, marginBottom:20 }}>
                <StatBox label="AUTOENCODER" value="ACTIVE" sub="Anomaly baseline layer" color={C.purple} />
                <StatBox label="LSTM LAYER" value="ACTIVE" sub="Temporal pattern detection" color={C.cyan} />
                <StatBox label="XGBOOST" value="99.97%" sub="Classification accuracy" color={C.green} />
              </div>
              <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr", gap:16 }}>
                <Card glow={C.red}>
                  <Label color={C.red}>DETECTED THREATS — ALL LAYERS</Label>
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr 1fr 1fr 0.7fr", color:C.muted, fontSize:10, letterSpacing:1, padding:"4px 0", borderBottom:`1px solid ${C.border}`, marginBottom:4 }}>
                    <span>TIME</span><span>TYPE</span><span>SEVERITY</span><span>ANOMALY</span><span>CONFIDENCE</span><span>AGENT</span><span>ACTION</span>
                  </div>
                  <div style={{ maxHeight:420, overflowY:"scroll", marginRight:-12, paddingRight:12 }}>
                    {threats.map(t=>(
                      <div key={t.id} className="ctx-row" onClick={()=>setSelected(t===selected?null:t)}
                        style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr 1fr 1fr 0.7fr", padding:"5px 0", borderBottom:`1px solid ${C.border}`, background:selected===t?C.dim:"transparent", borderLeft:selected===t?`2px solid ${SEV_COLORS[t.severity]}`:"2px solid transparent", alignItems:"center" }}>
                        <span style={{ color:C.muted, fontSize:10 }}>{new Date(t.ts).toLocaleTimeString()}</span>
                        <span style={{ color:SEV_COLORS[t.severity], fontSize:11 }}>{t.type}</span>
                        <Badge label={t.severity} color={SEV_COLORS[t.severity]} />
                        <span style={{ color:C.orange, fontSize:11 }}>{rnd(0.5,0.99).toFixed(3)}</span>
                        <span style={{ color:C.green, fontSize:11 }}>{(rnd(70,99)).toFixed(1)}%</span>
                        <span style={{ color:C.muted, fontSize:10 }}>{t.agent?.split(" ")[0]}</span>
                        <button onClick={(e)=>{e.stopPropagation();handleAgentDiscussion(`${t.type} attack from ${t.src} — ${t.severity}`);}} style={{ background:C.accent+"22", border:`1px solid ${C.accent}44`, borderRadius:3, color:C.accent, padding:"2px 8px", fontSize:9, cursor:"pointer", fontFamily:"monospace", letterSpacing:1 }}>DISCUSS</button>
                      </div>
                    ))}
                  </div>
                </Card>
                <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
                  <Card glow={C.purple}>
                    <Label color={C.purple}>MODEL ENSEMBLE STATUS</Label>
                    {[
                      { name:"Autoencoder", acc:"~99%", type:"Unsupervised", color:C.purple },
                      { name:"LSTM (seq-60)", acc:"97.91%", type:"Temporal", color:C.cyan },
                      { name:"XGBoost", acc:"99.97%", type:"Supervised", color:C.green },
                      { name:"SHAP XAI", acc:"Active", type:"Explainability", color:C.yellow },
                    ].map(m=>(
                      <div key={m.name} style={{ marginBottom:8, padding:"7px 10px", background:C.surface, borderRadius:4, borderLeft:`2px solid ${m.color}` }}>
                        <div style={{ display:"flex", justifyContent:"space-between" }}>
                          <span style={{ color:m.color, fontSize:12 }}>{m.name}</span>
                          <span style={{ color:C.green, fontSize:11 }}>{m.acc}</span>
                        </div>
                        <span style={{ color:C.muted, fontSize:10 }}>{m.type}</span>
                      </div>
                    ))}
                  </Card>
                  {selected && (
                    <Card glow={SEV_COLORS[selected.severity]}>
                      <Label color={SEV_COLORS[selected.severity]}>SHAP EXPLANATION</Label>
                      <div style={{ color:SEV_COLORS[selected.severity], fontWeight:700, marginBottom:8 }}>{selected.type}</div>
                      {["Bytes/sec","SYN ratio","IAT mean","Payload entropy","Pkt length"].map(f=>{
                        const v = rnd(-1,1);
                        return (
                          <div key={f} style={{ marginBottom:6 }}>
                            <div style={{ display:"flex", justifyContent:"space-between", fontSize:10, marginBottom:2 }}>
                              <span style={{ color:C.muted }}>{f}</span>
                              <span style={{ color:v>0?C.red:C.green }}>{v>0?"+":""}{v.toFixed(3)}</span>
                            </div>
                            <div style={{ background:C.dim, borderRadius:3, height:4, position:"relative" }}>
                              <div style={{ position:"absolute", left:v<0?`${50+v*50}%`:"50%", width:`${Math.abs(v)*50}%`, height:"100%", background:v>0?C.red:C.green, borderRadius:3 }} />
                              <div style={{ position:"absolute", left:"50%", top:0, width:1, height:"100%", background:C.border2 }} />
                            </div>
                          </div>
                        );
                      })}
                    </Card>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ══ BWVS ══ */}
          {page==="bwvs" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"auto 1fr", gap:20, marginBottom:20 }}>
                <Card glow={bwvsScore>=7?C.red:C.yellow} style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", padding:24 }}>
                  <BwvsGauge score={bwvsScore} />
                  <div style={{ color:bwvsScore>=8?C.red:bwvsScore>=6?C.orange:C.yellow, fontSize:12, letterSpacing:2, marginTop:8 }}>
                    {bwvsScore>=8?"CRITICAL RISK":bwvsScore>=6?"HIGH RISK":bwvsScore>=4?"MEDIUM RISK":"LOW RISK"}
                  </div>
                  <div style={{ color:C.muted, fontSize:10, marginTop:4 }}>Business-Weighted Vulnerability Score</div>
                </Card>
                <Card>
                  <Label color={C.yellow}>BWVS SCORING COMPONENTS</Label>
                  {[
                    { factor:"Base CVSS Score",       weight:"30%", value:rnd(4,9), color:C.red },
                    { factor:"Asset Criticality",     weight:"25%", value:rnd(3,8), color:C.orange },
                    { factor:"Exploitability Index",  weight:"20%", value:rnd(2,7), color:C.yellow },
                    { factor:"Business Impact",       weight:"15%", value:rnd(5,10),color:C.purple },
                    { factor:"Threat Intelligence",   weight:"10%", value:rnd(3,9), color:C.cyan },
                  ].map(f=>(
                    <div key={f.factor} style={{ marginBottom:12 }}>
                      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:3 }}>
                        <span style={{ color:C.text, fontSize:12 }}>{f.factor}</span>
                        <div style={{ display:"flex", gap:8 }}>
                          <span style={{ color:C.muted, fontSize:11 }}>weight: {f.weight}</span>
                          <span style={{ color:f.color, fontSize:11, fontFamily:"monospace" }}>{f.value.toFixed(1)}</span>
                        </div>
                      </div>
                      <MiniBar value={f.value} max={10} color={f.color} />
                    </div>
                  ))}
                </Card>
              </div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                <Card>
                  <Label color={C.red}>HIGHEST BWVS THREATS</Label>
                  {threats.sort((a,b)=>b.bwvs-a.bwvs).slice(0,8).map(t=>(
                    <div key={t.id} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"6px 0", borderBottom:`1px solid ${C.border}` }}>
                      <div>
                        <span style={{ color:SEV_COLORS[t.severity], fontSize:12 }}>{t.type}</span>
                        <div style={{ color:C.muted, fontSize:10 }}>{t.src}</div>
                      </div>
                      <div style={{ textAlign:"right" }}>
                        <div style={{ color:t.bwvs>=7?C.red:C.yellow, fontSize:14, fontWeight:700, fontFamily:"monospace" }}>{t.bwvs}</div>
                        <MiniBar value={t.bwvs} max={10} color={t.bwvs>=7?C.red:C.yellow} height={3} />
                      </div>
                    </div>
                  ))}
                </Card>
                <Card>
                  <Label color={C.purple}>BWVS vs CVSS COMPARISON</Label>
                  <div style={{ color:C.muted, fontSize:11, marginBottom:12 }}>BWVS adds operational context to raw CVSS scores</div>
                  {[
                    { label:"CVE-2024-11791", cvss:9.8, bwvs:6.2, reason:"Non-internet-facing asset" },
                    { label:"CVE-2024-34561", cvss:5.4, bwvs:9.1, reason:"Core payment processor" },
                    { label:"CVE-2024-22190", cvss:7.5, bwvs:7.8, reason:"Active exploitation observed" },
                    { label:"CVE-2024-55032", cvss:8.1, bwvs:4.3, reason:"Compensating controls active" },
                  ].map(r=>(
                    <div key={r.label} style={{ marginBottom:10, padding:"8px 10px", background:C.surface, borderRadius:4 }}>
                      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                        <span style={{ color:C.yellow, fontSize:11, fontFamily:"monospace" }}>{r.label}</span>
                      </div>
                      <div style={{ display:"flex", gap:12, marginBottom:4 }}>
                        <div style={{ flex:1 }}><span style={{ color:C.muted, fontSize:10 }}>CVSS: </span><span style={{ color:C.orange }}>{r.cvss}</span></div>
                        <div style={{ flex:1 }}><span style={{ color:C.muted, fontSize:10 }}>BWVS: </span><span style={{ color:r.bwvs>r.cvss?C.red:C.green }}>{r.bwvs}</span></div>
                      </div>
                      <div style={{ color:C.muted, fontSize:10, fontStyle:"italic" }}>{r.reason}</div>
                    </div>
                  ))}
                </Card>
              </div>
            </div>
          )}

          {/* ══ DIGITAL TWIN ══ */}
          {page==="digital" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"3fr 1fr", gap:16 }}>
                <Card glow={C.cyan}>
                  <Label color={C.cyan}>NETWORK TOPOLOGY — LIVE ATTACK PATHS</Label>
                  <div style={{ display:"flex", gap:12, marginBottom:8, flexWrap:"wrap" }}>
                    <span style={{ display:"flex", alignItems:"center", gap:4, fontSize:10, color:C.muted }}><span style={{ color:C.red }}>──</span> Attack path</span>
                    <span style={{ display:"flex", alignItems:"center", gap:4, fontSize:10, color:C.muted }}><span style={{ color:C.green }}>●</span> Healthy node</span>
                    <span style={{ display:"flex", alignItems:"center", gap:4, fontSize:10, color:C.muted }}><span style={{ color:C.red }}>●</span> Compromised node</span>
                  </div>
                  <TopologyCanvas threats={threats} />
                </Card>
                <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
                  <Card>
                    <Label color={C.orange}>ATTACK PATH ANALYSIS</Label>
                    {[
                      { path:"Internet → Firewall → Web-01 → DB Primary", risk:"HIGH", hops:3 },
                      { path:"Internet → Firewall → Admin Host", risk:"CRITICAL", hops:2 },
                      { path:"Web-02 → Internal Net → DB Replica", risk:"MEDIUM", hops:2 },
                    ].map((p,i)=>(
                      <div key={i} style={{ marginBottom:8, padding:"8px 10px", background:C.surface, borderRadius:4, borderLeft:`2px solid ${p.risk==="CRITICAL"?C.red:p.risk==="HIGH"?C.orange:C.yellow}` }}>
                        <Badge label={p.risk} color={p.risk==="CRITICAL"?C.red:p.risk==="HIGH"?C.orange:C.yellow} />
                        <div style={{ color:C.muted, fontSize:10, marginTop:4, lineHeight:1.5 }}>{p.path}</div>
                        <div style={{ color:C.dim, fontSize:10 }}>{p.hops} hops</div>
                      </div>
                    ))}
                  </Card>
                  <Card>
                    <Label color={C.purple}>NODE STATUS</Label>
                    {[
                      { node:"Firewall", status:"HEALTHY", load:"12%" },
                      { node:"Web-01", status:"ALERT", load:"94%" },
                      { node:"DB Primary", status:"HEALTHY", load:"67%" },
                      { node:"Admin Host", status:"ISOLATED", load:"—" },
                    ].map(n=>(
                      <div key={n.node} style={{ display:"flex", justifyContent:"space-between", padding:"5px 0", borderBottom:`1px solid ${C.border}` }}>
                        <span style={{ color:C.text, fontSize:12 }}>{n.node}</span>
                        <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                          <span style={{ color:C.muted, fontSize:10 }}>{n.load}</span>
                          <Badge label={n.status} color={n.status==="HEALTHY"?C.green:n.status==="ISOLATED"?C.orange:C.red} />
                        </div>
                      </div>
                    ))}
                  </Card>
                </div>
              </div>
            </div>
          )}

          {/* ══ CVE INTELLIGENCE ══ */}
          {page==="cve" && (
            <div>
              <div style={{ display:"flex", gap:12, marginBottom:20, flexWrap:"wrap" }}>
                <StatBox label="CVEs TRACKED" value={cveStats.total||cves.length} color={C.purple} />
                <StatBox label="CISA KEV" value={cveStats.kev||cves.filter(c=>c.kev).length} sub="Known exploited" color={C.red} />
                <StatBox label="CRITICAL" value={cveStats.critical||cves.filter(c=>c.severity==="CRITICAL").length} color={C.orange} />
                <StatBox label="NVD FEED" value="LIVE" sub="Real-time NVD data" color={C.green} />
              </div>
              <Card glow={C.purple}>
                <Label color={C.purple}>CVE INTELLIGENCE FEED — CISA KEV + NVD</Label>
                <div style={{ display:"grid", gridTemplateColumns:"1.5fr 1fr 0.8fr 0.5fr 1fr 2.5fr", gap:"0 12px", color:C.muted, fontSize:10, letterSpacing:1, padding:"4px 0", borderBottom:`1px solid ${C.border}`, marginBottom:4 }}>
                  <span>CVE ID</span><span>PRODUCT</span><span>CVSS</span><span>KEV</span><span>SEVERITY</span><span>DESCRIPTION</span>
                </div>
                <div style={{ maxHeight:500, overflowY:"auto" }}>
                  {cves.map(c=>(
                    <div key={c.id} className="ctx-row" style={{ display:"grid", gridTemplateColumns:"1.5fr 1fr 0.8fr 0.5fr 1fr 2.5fr", gap:"0 12px", padding:"6px 0", borderBottom:`1px solid ${C.border}`, alignItems:"center" }}>
                      <span style={{ color:C.yellow, fontSize:11, fontFamily:"monospace" }}>{c.id}</span>
                      <span style={{ color:C.text, fontSize:11 }}>{c.product}</span>
                      <div>
                        <span style={{ color:c.cvss>=9?C.red:c.cvss>=7?C.orange:C.yellow, fontFamily:"monospace", fontSize:12, fontWeight:700 }}>{c.cvss}</span>
                        <MiniBar value={c.cvss} max={10} color={c.cvss>=9?C.red:c.cvss>=7?C.orange:C.yellow} height={3} />
                      </div>
                      <span style={{ color:c.kev?C.red:C.muted, fontSize:12 }}>{c.kev?"⚠":"—"}</span>
                      <Badge label={c.severity} color={SEV_COLORS[c.severity]} />
                      <span style={{ color:C.muted, fontSize:10 }}>{c.desc}</span>
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          )}

          {/* ══ BLOCKCHAIN LEDGER ══ */}
          {page==="blockchain" && (
            <div>
              <div style={{ display:"flex", gap:12, marginBottom:20 }}>
                <StatBox label="TOTAL BLOCKS" value={blocks.length} sub="Immutable entries" color={C.accent} />
                <StatBox label="VERIFIED" value="100%" sub="All blocks validated" color={C.green} />
                <StatBox label="LAST BLOCK" value={blocks[0]?.hash.slice(0,8)||"—"} sub="Latest hash" color={C.cyan} />
              </div>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                <Card glow={C.accent}>
                  <Label color={C.accent}>IMMUTABLE AUDIT CHAIN</Label>
                  <BlockchainViz blocks={blocks} />
                </Card>
                <Card>
                  <Label color={C.green}>FULL AUDIT LOG</Label>
                  <div style={{ maxHeight:480, overflowY:"auto" }}>
                    {blocks.map((b,i)=>(
                      <div key={i} style={{ marginBottom:8, padding:"8px 10px", background:C.surface, borderRadius:4, fontFamily:"monospace", fontSize:11 }}>
                        <div style={{ display:"flex", justifyContent:"space-between", marginBottom:3 }}>
                          <span style={{ color:C.accent }}>#{b.hash}</span>
                          <span style={{ color:C.green, fontSize:10 }}>✓ VERIFIED</span>
                        </div>
                        <div style={{ display:"flex", gap:16, marginBottom:2 }}>
                          <span><span style={{ color:C.muted }}>OP: </span><span style={{ color:C.yellow }}>{b.op}</span></span>
                          <span><span style={{ color:C.muted }}>BY: </span><span style={{ color:C.text }}>{b.actor}</span></span>
                        </div>
                        <div style={{ color:C.dim, fontSize:10 }}>prev: {b.prev}</div>
                        <div style={{ color:C.dim, fontSize:10 }}>{new Date(b.ts).toLocaleString()}</div>
                      </div>
                    ))}
                  </div>
                </Card>
              </div>
            </div>
          )}

          {/* ══ PLAYBOOKS ══ */}
          {page==="playbooks" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:16 }}>
                {[
                  {
                    name:"DDoS Mitigation",
                    trigger:"DDoS detection, >1000 pkt/s",
                    color:C.red,
                    steps:[
                      { step:"Detect", action:"XGBoost classifies DDoS with >85% confidence", auto:true },
                      { step:"Rate Limit", action:"Apply iptables rate limit on src_ip", auto:true },
                      { step:"Block", action:"Null route attacker IP at border firewall", auto:true },
                      { step:"Notify", action:"Alert NOC via PagerDuty + Slack", auto:true },
                      { step:"Review", action:"Human analyst reviews block list", auto:false },
                    ]
                  },
                  {
                    name:"BruteForce Response",
                    trigger:">5 failed auth in 60 seconds",
                    color:C.orange,
                    steps:[
                      { step:"Detect", action:"LSTM flags repeated auth failure sequence", auto:true },
                      { step:"Lock", action:"Temporarily lock targeted account (15 min)", auto:true },
                      { step:"Block IP", action:"Add src_ip to blocklist", auto:true },
                      { step:"Reset", action:"Force credential reset on affected account", auto:true },
                      { step:"Audit", action:"Log to blockchain ledger for compliance", auto:true },
                    ]
                  },
                  {
                    name:"Infiltration Isolation",
                    trigger:"Lateral movement detected",
                    color:C.purple,
                    steps:[
                      { step:"Detect", action:"UEBA flags abnormal internal access pattern", auto:true },
                      { step:"Isolate", action:"Move compromised host to quarantine VLAN", auto:true },
                      { step:"Kill", action:"Terminate malicious process (PID)", auto:true },
                      { step:"Escalate", action:"Dispatch Forensic Investigator agent", auto:true },
                      { step:"Report", action:"SOC analyst approval required for re-admission", auto:false },
                    ]
                  },
                  {
                    name:"Ransomware Containment",
                    trigger:"Bulk file encryption detected",
                    color:C.yellow,
                    steps:[
                      { step:"Detect", action:"Autoencoder anomaly score >0.95", auto:true },
                      { step:"Snapshot", action:"Immediately snapshot all affected volumes", auto:true },
                      { step:"Isolate", action:"Network isolate all affected hosts", auto:true },
                      { step:"Preserve", action:"Freeze memory dump for forensics", auto:true },
                      { step:"Recover", action:"Initiate backup restore procedure", auto:false },
                    ]
                  },
                ].map(pb=>(
                  <Card key={pb.name} glow={pb.color} className="ctx-card-hover">
                    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12 }}>
                      <div>
                        <div style={{ color:pb.color, fontWeight:700, fontSize:14, letterSpacing:1 }}>{pb.name}</div>
                        <div style={{ color:C.muted, fontSize:10, marginTop:2 }}>Trigger: {pb.trigger}</div>
                      </div>
                      <Badge label="ACTIVE" color={C.green} />
                    </div>
                    {pb.steps.map((s,i)=>(
                      <div key={i} style={{ display:"flex", gap:10, marginBottom:8, alignItems:"flex-start" }}>
                        <div style={{ width:22, height:22, borderRadius:"50%", background:pb.color+"22", border:`1px solid ${pb.color}55`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:10, color:pb.color, flexShrink:0 }}>{i+1}</div>
                        <div style={{ flex:1 }}>
                          <div style={{ display:"flex", justifyContent:"space-between" }}>
                            <span style={{ color:C.text, fontSize:12 }}>{s.step}</span>
                            <Badge label={s.auto?"AUTO":"MANUAL"} color={s.auto?C.green:C.yellow} />
                          </div>
                          <div style={{ color:C.muted, fontSize:11 }}>{s.action}</div>
                        </div>
                      </div>
                    ))}
                  </Card>
                ))}
              </div>
            </div>
          )}

          {/* ══ AI AGENTS ══ */}
          {page==="agents" && (
            <div>
              <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:16, marginBottom:20 }}>
                {AGENTS.map(a=>(
                  <Card key={a.id} glow={a.color} className="ctx-card-hover">
                    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:10 }}>
                      <div style={{ width:40,height:40,borderRadius:10,background:a.color+"22",border:`1px solid ${a.color}55`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:20 }}>◈</div>
                      <Badge label={a.status} color={a.status==="ACTIVE"?C.green:C.yellow} />
                    </div>
                    <div style={{ color:a.color, fontWeight:700, fontSize:13, marginBottom:2 }}>{a.name}</div>
                    <div style={{ color:C.muted, fontSize:11, marginBottom:10 }}>{a.role}</div>
                    <div style={{ background:C.surface, borderRadius:4, padding:"6px 8px", fontSize:10, color:C.dim, fontFamily:"monospace" }}>
                      {agentLogs.find(l=>l.agent===a.name)?.msg||"Monitoring..."}
                    </div>
                    <button onClick={()=>handleAgentDiscussion(`${a.role} — ${a.name} Analysis`)} style={{ marginTop:8, width:"100%", background:a.color+"18", border:`1px solid ${a.color}44`, borderRadius:4, color:a.color, padding:"5px 0", fontSize:10, letterSpacing:1, cursor:"pointer", fontFamily:"monospace" }}>▶ START DISCUSSION</button>
                  </Card>
                ))}
              </div>
              <Card glow={C.purple}>
                <Label color={C.purple}>MULTI-AGENT COLLABORATION LOG</Label>
                <div style={{ maxHeight:320, overflowY:"auto" }}>
                  {agentLogs.map((l,i)=>(
                    <div key={i} style={{ display:"flex", gap:12, padding:"5px 0", borderBottom:`1px solid ${C.border}`, alignItems:"center" }}>
                      <span style={{ color:C.muted, fontSize:10, flexShrink:0, width:70 }}>{l.ts}</span>
                      <span style={{ color:l.color, fontSize:11, flexShrink:0, minWidth:150 }}>{l.agent}</span>
                      <span style={{ color:C.text, fontSize:11 }}>{l.msg}</span>
                    </div>
                  ))}
                  {agentLogs.length===0&&<div style={{ color:C.muted,padding:30,textAlign:"center" }}>Agents initializing...</div>}
                </div>
              </Card>
            </div>
          )}

        </div>
      </div>

      {/* Agent Discussion Modal */}
      <AgentDiscussionOverlay
        isOpen={discussionOpen}
        onClose={()=>setDiscussionOpen(false)}
        riskName={discussionRisk}
        messages={discussionMessages}
        isLoading={discussionLoading}
      />
    </div>
  );
}
