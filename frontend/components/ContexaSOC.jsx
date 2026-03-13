"use client";

import { useState, useEffect, useRef, useCallback, useMemo } from "react";

// ─── PALETTE & CONSTANTS ───────────────────────────────────────────────────
const C = {
  bg:      "#060B1A",
  surface: "#0B1224",
  card:    "#121A33",
  border:  "rgba(99,102,241,0.25)",
  border2: "rgba(99,102,241,0.35)",
  text:    "#E6EDF8",
  muted:   "#9FB2D4",
  dim:     "#7F93B8",
  accent:  "#22D3EE",
  cyan:    "#22D3EE",
  indigo:  "#6366F1",
  blue:    "#60A5FA",
  purple:  "#A78BFA",
  teal:    "#34D399",
  green:   "#22C55E",
  warning: "#F59E0B",
  red:     "#EF4444",
  yellow:  "#A78BFA",
  orange:  "#F59E0B",
};

const NAV_ITEMS = [
  { id:"dashboard",  icon:"⬡", label:"SOC Overview" },
  { id:"sentinel",   icon:"◈", label:"Sentinel AI" },
  { id:"bwvs",       icon:"◎", label:"BWVS Scoring" },
  { id:"digital",    icon:"⬢", label:"Digital Twin" },
  { id:"cve",        icon:"◉", label:"CVE Intelligence" },
  { id:"playbooks",  icon:"▶", label:"Response Playbooks" },
  { id:"agents",     icon:"◈", label:"Agents & Model Health" },
  { id:"blockchain", icon:"⬡", label:"Audit Ledger" },
];

// ─── DATA GENERATORS ──────────────────────────────────────────────────────
const rnd = (a,b) => Math.random()*(b-a)+a;
const rndInt = (a,b) => Math.floor(rnd(a,b));
const rndIP = () => `${rndInt(10,220)}.${rndInt(0,255)}.${rndInt(0,255)}.${rndInt(1,254)}`;
const rndPick = arr => arr[rndInt(0,arr.length)];

const ATTACK_TYPES = ["DDoS","BruteForce","SQLi","PortScan","Bot","Infiltration","Ransomware","Phishing"];
const SEVERITIES = ["CRITICAL","HIGH","MEDIUM","LOW"];
const SEV_COLORS = { CRITICAL:C.red, HIGH:C.warning, MEDIUM:C.blue, LOW:C.green };

const AGENTS = [
  { id:"recon",    name:"Recon Analyst",        role:"Threat Reconnaissance",     color:C.cyan,   status:"ACTIVE" },
  { id:"vuln",     name:"Vuln Assessor",         role:"CVE Correlation",           color:C.purple, status:"ACTIVE" },
  { id:"forensic", name:"Forensic Investigator", role:"Evidence Collection",       color:C.blue,   status:"ACTIVE" },
  { id:"response", name:"Response Orchestrator", role:"Playbook Execution",        color:C.teal,   status:"ACTIVE" },
  { id:"intel",    name:"OSINT Collector",        role:"Threat Intelligence Feed",  color:C.indigo, status:"STANDBY" },
  { id:"risk",     name:"Business Risk Scorer",   role:"BWVS Calculation",         color:C.blue,   status:"ACTIVE" },
];

const STATIC_ML_HEALTH = {
  status: "PENDING INTEGRATION",
  modelVersion: "TBD",
  accuracy: 92.8,
  f1Score: 92.4,
  auc: 96.7,
  drift: 8.0,
  note: "Static preview metrics. Live ML telemetry will be wired once the model service is connected.",
};

const MODEL_HEALTH_SERIES = {
  accuracy: [89.4, 90.1, 91.3, 91.9, 92.8],
  f1Score: [88.9, 90.0, 90.9, 91.8, 92.4],
  auc: [94.8, 95.4, 95.9, 96.3, 96.7],
  drift: [6.2, 7.0, 7.7, 8.1, 8.0],
};

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const normalizePct = (value) => {
  if (typeof value !== "number" || Number.isNaN(value)) return null;
  return value <= 1 ? value * 100 : value;
};

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
      boxShadow: glow?"0 0 10px rgba(34,211,238,0.15)":"none",
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
      display:"inline-flex", width:"fit-content", justifySelf:"start", alignSelf:"center",
      fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace", fontWeight:700, letterSpacing:1,
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

function TinyMetricGraph({ points, color, max=100, invert=false }) {
  const w = 240;
  const h = 56;
  const pad = 6;
  const usableW = w - pad * 2;
  const usableH = h - pad * 2;
  const step = points.length > 1 ? usableW / (points.length - 1) : usableW;

  const normalize = (value) => {
    const clamped = Math.max(0, Math.min(max, value));
    const ratio = clamped / max;
    return invert ? ratio : 1 - ratio;
  };

  const coords = points.map((v, i) => {
    const x = pad + i * step;
    const y = pad + normalize(v) * usableH;
    return `${x},${y}`;
  });

  const line = coords.join(" ");
  const area = `${pad},${h - pad} ${line} ${pad + usableW},${h - pad}`;

  return (
    <svg width="100%" viewBox={`0 0 ${w} ${h}`} style={{ display:"block" }}>
      {[0.25, 0.5, 0.75].map((p) => (
        <line
          key={p}
          x1={pad}
          y1={pad + usableH * p}
          x2={pad + usableW}
          y2={pad + usableH * p}
          stroke={C.border2}
          strokeWidth="1"
          opacity="0.7"
        />
      ))}
      <polygon points={area} fill={color} opacity="0.14" />
      <polyline points={line} fill="none" stroke={color} strokeWidth="2" />
      {coords.map((pt, i) => {
        const [x, y] = pt.split(",");
        const isLast = i === coords.length - 1;
        return (
          <circle
            key={`${pt}-${i}`}
            cx={x}
            cy={y}
            r={isLast ? 3.4 : 2.2}
            fill={color}
            opacity={isLast ? 1 : 0.85}
          />
        );
      })}
    </svg>
  );
}

function ModelMetricGraph({ label, value, color, series, invert=false }) {
  return (
    <div style={{ background:C.surface, border:`1px solid ${color}33`, borderRadius:6, padding:"8px 10px" }}>
      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:6 }}>
        <span style={{ color:C.muted, fontSize:10 }}>{label}</span>
        <span style={{ color, fontSize:10, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>{value}%</span>
      </div>
      <TinyMetricGraph points={series} color={color} max={100} invert={invert} />
    </div>
  );
}

function MetricSparkCard({ label, value, color, series, invert=false }) {
  return (
    <div style={{ background:C.surface, border:`1px solid ${color}44`, borderRadius:8, padding:"10px 12px", boxShadow:`0 0 18px ${color}14` }}>
      <div style={{ color:C.text, fontSize:12, marginBottom:6 }}>{label}</div>
      <div style={{ color, fontSize:22, fontWeight:700, lineHeight:1, marginBottom:8, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>
        {value.toFixed(2)}%
      </div>
      <TinyMetricGraph points={series} color={color} max={100} invert={invert} />
    </div>
  );
}

function DriftGaugeCard({ value }) {
  const gaugeColor = value <= 10 ? C.green : value <= 20 ? C.yellow : C.orange;
  const pct = clamp(value, 0, 100) / 100;
  const cx = 64;
  const cy = 64;
  const r = 46;

  const polar = (p) => {
    const angle = Math.PI * (1 - p);
    return { x: cx + r * Math.cos(angle), y: cy - r * Math.sin(angle) };
  };

  const start = polar(0);
  const end = polar(pct);
  const largeArc = pct > 0.5 ? 1 : 0;

  return (
    <div style={{ background:C.surface, border:`1px solid ${gaugeColor}44`, borderRadius:8, padding:"10px 12px", boxShadow:`0 0 18px ${gaugeColor}14`, display:"flex", flexDirection:"column", justifyContent:"space-between" }}>
      <div style={{ color:C.text, fontSize:12, marginBottom:4 }}>Feature Drift</div>
      <div style={{ display:"flex", justifyContent:"center" }}>
        <svg width="128" height="86" viewBox="0 0 128 86">
          <path
            d={`M ${polar(0).x} ${polar(0).y} A ${r} ${r} 0 1 1 ${polar(1).x} ${polar(1).y}`}
            fill="none"
            stroke={C.border2}
            strokeWidth="10"
            strokeLinecap="round"
            opacity="0.8"
          />
          <path
            d={`M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${end.x} ${end.y}`}
            fill="none"
            stroke={gaugeColor}
            strokeWidth="10"
            strokeLinecap="round"
            style={{ filter:`drop-shadow(0 0 8px ${gaugeColor})` }}
          />
          <text x={64} y={58} textAnchor="middle" fill={gaugeColor} fontSize="18" fontWeight="700" fontFamily="'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace">
            {value.toFixed(1)}%
          </text>
        </svg>
      </div>
      <div style={{ color:C.muted, fontSize:10, textAlign:"center" }}>Lower is better</div>
    </div>
  );
}

function DriftBarsCard({ value }) {
  const labels = ["A1", "A2", "A3", "A4", "B5", "A8", "A10"];
  const base = [180, 115, 58, 43, 37, 31, 28];
  const severity = clamp(value / 20, 0.2, 1.2);
  const bars = base.map((b, i) => Math.max(10, Math.round(b * (1 - i * 0.04) * severity)));
  const maxBar = Math.max(...bars, 1);

  return (
    <div style={{ background:C.surface, border:`1px solid ${C.accent}33`, borderRadius:8, padding:"10px 12px" }}>
      <div style={{ color:C.text, fontSize:12 }}>Data Drift (Categorical)</div>
      <div style={{ color:C.muted, fontSize:10, marginBottom:6 }}>Top drifted categories</div>
      <div style={{ display:"grid", gridTemplateColumns:`repeat(${labels.length}, 1fr)`, alignItems:"end", gap:6, height:92, borderBottom:`1px solid ${C.border2}`, paddingBottom:6 }}>
        {bars.map((b, i) => (
          <div key={labels[i]} style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:4 }}>
            <div
              style={{
                width:"100%",
                maxWidth:28,
                height:`${Math.max(6, Math.round((b / maxBar) * 78))}px`,
                background:`linear-gradient(180deg, ${C.accent}, ${C.purple})`,
                borderRadius:3,
                boxShadow:`0 0 10px ${C.accent}33`,
              }}
            />
            <span style={{ color:C.muted, fontSize:9 }}>{labels[i]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function HealthRing({ value, color }) {
  const pct = clamp(value, 0, 100) / 100;
  const cx = 42;
  const cy = 42;
  const r = 30;
  const c = 2 * Math.PI * r;
  const dash = c * pct;
  const gap = c - dash;

  return (
    <svg width="84" height="84" viewBox="0 0 84 84" style={{ display:"block" }}>
      <circle cx={cx} cy={cy} r={r} stroke={C.border2} strokeWidth="8" fill="none" />
      <circle
        cx={cx}
        cy={cy}
        r={r}
        stroke={color}
        strokeWidth="8"
        fill="none"
        strokeLinecap="round"
        strokeDasharray={`${dash} ${gap}`}
        transform={`rotate(-90 ${cx} ${cy})`}
        style={{ filter:`drop-shadow(0 0 8px ${color})` }}
      />
      <text
        x={cx}
        y={cy + 5}
        textAnchor="middle"
        fill={color}
        fontSize="14"
        fontWeight="700"
        fontFamily="'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace"
      >
        {`${Math.round(value)}%`}
      </text>
    </svg>
  );
}

function ThroughputSpark({ value }) {
  const [phase, setPhase] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setPhase((p) => p + 1);
    }, 220);
    return () => clearInterval(timer);
  }, []);

  const bars = Array.from({ length: 28 }, (_, i) => {
    const base = 18 + (Math.sin((i + phase * 0.7) * 0.55) + 1) * 11;
    const ripple = (Math.cos((i * 0.85) - phase * 0.45) + 1) * 3;
    const scaled = base + ripple + Math.min(value, 80) * 0.16;
    return clamp(Math.round(scaled), 8, 40);
  });

  return (
    <div style={{ display:"flex", alignItems:"end", gap:2, height:44, overflow:"hidden" }}>
      {bars.map((h, i) => (
        <div
          key={i}
          style={{
            width:4,
            height:h,
            borderRadius:2,
            background:`linear-gradient(180deg, ${C.purple}, ${C.accent})`,
            boxShadow:`0 0 6px ${C.purple}55`,
            opacity: i > bars.length - 5 ? 1 : 0.82,
          }}
        />
      ))}
    </div>
  );
}

function AgentHealthPlate({ agent }) {
  const statusColor = agent.health === "OPTIMAL" ? C.green : agent.health === "HEALTHY" ? C.warning : C.red;
  return (
    <div
      style={{
        background:`linear-gradient(135deg, ${C.surface}, ${C.card})`,
        border:`1px solid ${agent.color}44`,
        borderRadius:10,
        padding:"10px 12px",
        boxShadow:`0 0 16px ${agent.color}1f`,
        position:"relative",
        overflow:"hidden",
      }}
    >
      <div
        style={{
          position:"absolute",
          inset:0,
          background:`linear-gradient(120deg, transparent 0%, ${agent.color}0d 50%, transparent 100%)`,
          pointerEvents:"none",
        }}
      />
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8, position:"relative" }}>
        <div style={{ color:agent.color, fontSize:12, fontWeight:600 }}>{agent.name}</div>
        <div style={{ display:"flex", gap:6, alignItems:"center" }}>
          <Badge label={agent.health} color={statusColor} />
          <span style={{ color:C.muted, fontSize:10, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>{agent.score}%</span>
        </div>
      </div>
      <div style={{ marginBottom:7, position:"relative" }}>
        <MiniBar value={agent.score} max={100} color={agent.color} height={5} />
      </div>
      <div style={{ color:C.dim, fontSize:10, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis", position:"relative" }}>
        {agent.lastMsg}
      </div>
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

function StatBox({ label, value, sub, color=C.accent, labelColor=C.muted, subColor=C.muted }) {
  return (
    <Card style={{ flex:1, minWidth:120 }}>
      <Label color={labelColor}>{label}</Label>
      <div style={{ color, fontSize:28, fontWeight:700, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace", lineHeight:1 }}>{value}</div>
      {sub && <div style={{ color:subColor, fontSize:11, marginTop:4 }}>{sub}</div>}
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
            <text x={n.x} y={n.y+26} textAnchor="middle" fontSize={9} fill={C.muted} fontFamily="'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace">{n.label}</text>
          </g>
        );
      })}
    </svg>
  );
}

// ─── BWVS GAUGE ───────────────────────────────────────────────────────────
function BwvsGauge({ score }) {
  const pct = clamp(score / 10, 0, 1);
  const r=60, cx=80, cy=80;
  const arc = (p, radius=r) => {
    const a = Math.PI + p*Math.PI;
    return { x: cx+radius*Math.cos(a), y: cy+radius*Math.sin(a) };
  };
  const start=arc(0), end=arc(pct);
  const color = score>=8?C.red:score>=6?C.orange:score>=4?C.yellow:C.green;
  return (
    <svg width={160} height={100} viewBox="0 0 160 100">
      <path d={`M ${arc(0,r).x} ${arc(0,r).y} A ${r} ${r} 0 1 1 ${arc(1,r).x} ${arc(1,r).y}`}
        fill="none" stroke={C.dim} strokeWidth={8} strokeLinecap="round" />
      <path d={`M ${start.x} ${start.y} A ${r} ${r} 0 0 1 ${end.x} ${end.y}`}
        fill="none" stroke={color} strokeWidth={8} strokeLinecap="round"
        style={{ filter:`drop-shadow(0 0 6px ${color})` }} />
      <text x={cx} y={cy+8} textAnchor="middle" fontSize={22} fontWeight={700} fill={color} fontFamily="'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace">{score.toFixed(1)}</text>
      <text x={cx} y={cy+22} textAnchor="middle" fontSize={9} fill={C.muted} fontFamily="'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace">BWVS SCORE</text>
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
              <span style={{ color:C.accent, fontSize:10, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>#{b.hash.slice(0,8)}</span>
              <span style={{ display:"flex", alignItems:"center", gap:4 }}>
                <span style={{ color:C.green, fontSize:9 }}>✓ VERIFIED</span>
              </span>
            </div>
            <div style={{ display:"flex", gap:16 }}>
              <div><span style={{ color:C.muted, fontSize:10 }}>OP: </span><span style={{ color:C.yellow, fontSize:10, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>{b.op}</span></div>
              <div><span style={{ color:C.muted, fontSize:10 }}>BY: </span><span style={{ color:C.text, fontSize:10 }}>{b.actor}</span></div>
            </div>
            <div style={{ color:C.dim, fontSize:9, marginTop:3, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>prev: {b.prev.slice(0,12)}...</div>
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
  const [modelHealthLive, setModelHealthLive] = useState(false);
  const [modelHealth, setModelHealth] = useState({
    ...STATIC_ML_HEALTH,
    source: "SIMULATED",
  });
  const [modelHealthSeries, setModelHealthSeries] = useState(MODEL_HEALTH_SERIES);

  const aiAgentHealth = useMemo(() => {
    const now = Date.now();
    const perAgent = AGENTS.map((agent) => {
      const logs = agentLogs.filter((l) => l.agent === agent.name);
      const latest = logs[0];
      const statusBase = agent.status === "ACTIVE" ? 82 : 66;
      const activityBoost = Math.min(logs.length * 2, 12);
      const freshnessBoost = latest?.at
        ? (now - latest.at) <= 10000
          ? 8
          : (now - latest.at) <= 30000
            ? 4
            : 0
        : 0;

      const score = Math.min(99, Math.max(45, Math.round(statusBase + activityBoost + freshnessBoost)));
      const health = score >= 90 ? "OPTIMAL" : score >= 75 ? "HEALTHY" : "DEGRADED";

      return {
        id: agent.id,
        name: agent.name,
        color: agent.color,
        status: agent.status,
        score,
        health,
        lastMsg: latest?.msg || "Monitoring...",
      };
    });

    const overallScore = Math.round(
      perAgent.reduce((acc, a) => acc + a.score, 0) / Math.max(perAgent.length, 1)
    );
    const activeCount = AGENTS.filter((a) => a.status === "ACTIVE").length;
    const recentLogCount = agentLogs.filter((l) => l.at && (now - l.at) <= 60000).length;
    const avgRecencySec = Math.round(
      perAgent.reduce((acc, a) => {
        const log = agentLogs.find((l) => l.agent === a.name && l.at);
        if (!log) return acc + 60;
        return acc + Math.min(60, (now - log.at) / 1000);
      }, 0) / Math.max(perAgent.length, 1)
    );

    return {
      overallScore,
      activeCount,
      totalAgents: AGENTS.length,
      throughputPerMin: recentLogCount,
      avgRecencySec,
      perAgent,
    };
  }, [agentLogs]);

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

  // Poll model health endpoint. Falls back to simulated mode if endpoint is unavailable.
  useEffect(() => {
    let cancelled = false;
    const endpoint = process.env.NEXT_PUBLIC_MODEL_HEALTH_API || "http://localhost:8000/api/ml/health";

    const readSeries = (series, fallback) => {
      if (!Array.isArray(series) || series.length === 0) return fallback;
      const normalized = series
        .map((v) => normalizePct(v))
        .filter((v) => typeof v === "number")
        .map((v) => +clamp(v, 0, 100).toFixed(2));
      return normalized.length > 0 ? normalized.slice(-5) : fallback;
    };

    const pollModelHealth = async () => {
      try {
        const res = await fetch(endpoint, { cache: "no-store" });
        if (!res.ok) throw new Error(`Model health endpoint returned ${res.status}`);

        const data = await res.json();
        const accuracy = normalizePct(data?.accuracy);
        const f1Score = normalizePct(data?.f1Score ?? data?.f1 ?? data?.f1_score);
        const auc = normalizePct(data?.auc ?? data?.aucRoc ?? data?.auc_roc);
        const drift = normalizePct(data?.drift ?? data?.featureDrift ?? data?.feature_drift);

        if ([accuracy, f1Score, auc, drift].some((v) => v === null)) {
          throw new Error("Model health payload missing required metrics");
        }

        const nextAccuracy = +clamp(accuracy, 0, 100).toFixed(2);
        const nextF1 = +clamp(f1Score, 0, 100).toFixed(2);
        const nextAuc = +clamp(auc, 0, 100).toFixed(2);
        const nextDrift = +clamp(drift, 0, 100).toFixed(2);

        if (cancelled) return;

        setModelHealthLive(true);
        setModelHealth({
          status: data?.status || "LIVE",
          modelVersion: data?.modelVersion || data?.model_version || "LIVE",
          accuracy: nextAccuracy,
          f1Score: nextF1,
          auc: nextAuc,
          drift: nextDrift,
          note: data?.note || "Live model telemetry from backend endpoint.",
          source: "API",
        });

        setModelHealthSeries((prev) => ({
          accuracy: readSeries(data?.series?.accuracy, [...prev.accuracy.slice(-4), nextAccuracy]),
          f1Score: readSeries(data?.series?.f1Score || data?.series?.f1 || data?.series?.f1_score, [...prev.f1Score.slice(-4), nextF1]),
          auc: readSeries(data?.series?.auc || data?.series?.aucRoc || data?.series?.auc_roc, [...prev.auc.slice(-4), nextAuc]),
          drift: readSeries(data?.series?.drift || data?.series?.featureDrift || data?.series?.feature_drift, [...prev.drift.slice(-4), nextDrift]),
        }));
      } catch {
        if (!cancelled) setModelHealthLive(false);
      }
    };

    pollModelHealth();
    const timer = setInterval(pollModelHealth, 10000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  // Simulated movement for model metrics until real ML endpoint is connected.
  useEffect(() => {
    if (modelHealthLive) return;

    const nudge = (value, min, max, step) => +clamp(value + rnd(-step, step), min, max).toFixed(2);

    const timer = setInterval(() => {
      setModelHealth((prev) => {
        const accuracy = nudge(prev.accuracy, 86, 97, 0.35);
        const f1Score = nudge(prev.f1Score, 85, 96, 0.4);
        const auc = nudge(prev.auc, 92, 99, 0.28);
        const drift = nudge(prev.drift, 3, 18, 0.55);

        setModelHealthSeries((seriesPrev) => ({
          accuracy: [...seriesPrev.accuracy.slice(-4), accuracy],
          f1Score: [...seriesPrev.f1Score.slice(-4), f1Score],
          auc: [...seriesPrev.auc.slice(-4), auc],
          drift: [...seriesPrev.drift.slice(-4), drift],
        }));

        return {
          ...prev,
          status: "SIMULATED LIVE",
          modelVersion: prev.modelVersion || "TBD",
          accuracy,
          f1Score,
          auc,
          drift,
          note: "Simulated live telemetry active. Auto-switches to real backend model metrics when endpoint is available.",
          source: "SIMULATED",
        };
      });
    }, 1800);

    return () => clearInterval(timer);
  }, [modelHealthLive]);

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
        at: Date.now(),
      },...p].slice(0,50));
    },1200);
    return ()=>clearInterval(t);
  },[running]);

  const critCount = threats.filter(t=>t.severity==="CRITICAL").length;
  const activeThreats = threats.filter(t=>t.status!=="RESOLVED").length;

  return (
    <div style={{ display:"flex", height:"100vh", background:C.bg, color:C.text, fontFamily:"'Inter','Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif", fontSize:13, overflow:"hidden" }}>
      <style>{`
        @keyframes ctxPing{0%{transform:scale(1);opacity:0.4}100%{transform:scale(2.8);opacity:0}}
        @keyframes ctxFade{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
        @keyframes ctxDotBounce{0%,80%,100%{transform:scale(0.4);opacity:0.3}40%{transform:scale(1);opacity:1}}
        @keyframes ctxScan{0%{top:-5%}100%{top:105%}}
        ::-webkit-scrollbar{width:3px;background:transparent}
        ::-webkit-scrollbar-thumb{background:rgba(99,102,241,0.45);border-radius:2px}
        .ctx-nav:hover{background:#0f0f22!important;color:#fff!important}
        .ctx-row:hover{background:#0d0d20!important;cursor:pointer}
        .ctx-card-hover:hover{border-color:rgba(34,211,238,0.6)!important;filter:brightness(1.06);transform:translateY(-1px);transition:all 0.2s}
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
            letterSpacing:2, cursor:"pointer", fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace",
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
                          <button onClick={(e)=>{e.stopPropagation();handleAgentDiscussion(`${t.type} attack from ${t.src} — ${t.severity}`);}} style={{ background:C.accent+"22", border:`1px solid ${C.accent}44`, borderRadius:3, color:C.accent, padding:"1px 6px", fontSize:9, cursor:"pointer", fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>DISCUSS</button>
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
                        <span style={{ color:C.yellow, fontSize:11, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>{c.id}</span>
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
                      <div style={{ color:C.accent, fontSize:10, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>#{b.hash.slice(0,10)}</div>
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
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr", gap:12, marginBottom:20 }}>
                <StatBox label="AUTOENCODER" value="ACTIVE" sub="Anomaly baseline layer" color={C.purple} />
                <StatBox label="LSTM LAYER" value="ACTIVE" sub="Temporal pattern detection" color={C.cyan} />
                <StatBox label="ISOLATION FOREST" value="ACTIVE" sub="Outlier isolation scoring" color={C.orange} />
                <StatBox label="XGBOOST" value="89.47%" sub="Classification accuracy" color={C.green} />
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
                        <button onClick={(e)=>{e.stopPropagation();handleAgentDiscussion(`${t.type} attack from ${t.src} — ${t.severity}`);}} style={{ background:C.accent+"22", border:`1px solid ${C.accent}44`, borderRadius:3, color:C.accent, padding:"2px 8px", fontSize:9, cursor:"pointer", fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace", letterSpacing:1 }}>DISCUSS</button>
                      </div>
                    ))}
                  </div>
                </Card>
                <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
                  <Card glow={C.purple}>
                    <Label color={C.purple}>MODEL ENSEMBLE STATUS</Label>
                    {[
                      { name:"Autoencoder", acc:"88.40%", type:"Unsupervised", color:C.purple },
                      { name:"LSTM (seq-60)", acc:"87.91%", type:"Temporal", color:C.cyan },
                      { name:"Isolation Forest", acc:"86.63%", type:"Outlier Detection", color:C.orange },
                      { name:"XGBoost", acc:"89.47%", type:"Supervised", color:C.green },
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
                          <span style={{ color:f.color, fontSize:11, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>{f.value.toFixed(1)}</span>
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
                        <div style={{ color:t.bwvs>=7?C.red:C.yellow, fontSize:14, fontWeight:700, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>{t.bwvs}</div>
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
                        <span style={{ color:C.yellow, fontSize:11, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>{r.label}</span>
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
                <StatBox label="CVEs TRACKED" value={cveStats.total||cves.length} color="#62E8FF" labelColor="#9AF2FF" subColor="#62E8FF" />
                <StatBox label="CISA KEV" value={cveStats.kev||cves.filter(c=>c.kev).length} sub="Known exploited" color="#7C5CFF" labelColor="#B4A4FF" subColor="#7C5CFF" />
                <StatBox label="CRITICAL" value={cveStats.critical||cves.filter(c=>c.severity==="CRITICAL").length} color="#FFC857" labelColor="#FFE08F" subColor="#FFC857" />
                <StatBox label="NVD FEED" value="LIVE" sub="Real-time NVD data" color="#4CFFB8" labelColor="#8AFFD1" subColor="#4CFFB8" />
              </div>
              <Card glow={C.purple}>
                <Label color={C.purple}>CVE INTELLIGENCE FEED — CISA KEV + NVD</Label>
                <div style={{ display:"grid", gridTemplateColumns:"1.5fr 1fr 0.8fr 0.5fr 1fr 2.5fr", gap:"0 12px", color:C.muted, fontSize:10, letterSpacing:1, padding:"4px 0", borderBottom:`1px solid ${C.border}`, marginBottom:4 }}>
                  <span>CVE ID</span><span>PRODUCT</span><span>CVSS</span><span>KEV</span><span>SEVERITY</span><span>DESCRIPTION</span>
                </div>
                <div style={{ maxHeight:500, overflowY:"auto" }}>
                  {cves.map(c=>(
                    <div key={c.id} className="ctx-row" style={{ display:"grid", gridTemplateColumns:"1.5fr 1fr 0.8fr 0.5fr 1fr 2.5fr", gap:"0 12px", padding:"6px 0", borderBottom:`1px solid ${C.border}`, alignItems:"center" }}>
                      <span style={{ color:C.yellow, fontSize:11, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>{c.id}</span>
                      <span style={{ color:C.text, fontSize:11 }}>{c.product}</span>
                      <div>
                        <span style={{ color:c.cvss>=9?C.red:c.cvss>=7?C.orange:C.yellow, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace", fontSize:12, fontWeight:700 }}>{c.cvss}</span>
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
                      <div key={i} style={{ marginBottom:8, padding:"8px 10px", background:C.surface, borderRadius:4, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace", fontSize:11 }}>
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
              <div style={{ display:"grid", gridTemplateColumns:"1.45fr 1fr", gap:16, alignItems:"stretch" }}>
                <div style={{ display:"flex", flexDirection:"column", gap:16, height:"100%" }}>
                  <Card glow={C.green}>
                    <Label color={C.green}>AGENTS HEALTH — DYNAMIC</Label>
                    <div style={{ background:`linear-gradient(135deg, ${C.surface}, ${C.card})`, border:`1px solid ${C.cyan}33`, borderRadius:10, padding:"10px 12px", marginBottom:12 }}>
                      <div style={{ display:"grid", gridTemplateColumns:"1.2fr 1fr 1fr 1fr", gap:10, alignItems:"center" }}>
                        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                          <HealthRing value={aiAgentHealth.overallScore} color={aiAgentHealth.overallScore >= 85 ? C.green : aiAgentHealth.overallScore >= 70 ? C.warning : C.red} />
                          <div>
                            <div style={{ color:C.muted, fontSize:10 }}>Overall Health</div>
                            <div style={{ color:C.text, fontSize:12 }}>Live agent readiness</div>
                          </div>
                        </div>
                        <div style={{ background:C.card, border:`1px solid ${C.cyan}33`, borderRadius:8, padding:"8px 10px" }}>
                          <div style={{ color:C.muted, fontSize:10, marginBottom:4 }}>Agents Online</div>
                          <div style={{ color:C.cyan, fontSize:24, lineHeight:1, fontWeight:700, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>{aiAgentHealth.activeCount}/{aiAgentHealth.totalAgents}</div>
                        </div>
                        <div style={{ background:C.card, border:`1px solid ${C.indigo}44`, borderRadius:8, padding:"8px 10px" }}>
                          <div style={{ color:C.text, fontSize:11, fontWeight:600, letterSpacing:0.5, marginBottom:4 }}>Throughput</div>
                          <ThroughputSpark value={aiAgentHealth.throughputPerMin} />
                          <div style={{ color:C.cyan, fontSize:14, marginTop:6, fontWeight:700, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>{aiAgentHealth.throughputPerMin}/min</div>
                        </div>
                        <div style={{ background:C.card, border:`1px solid ${C.blue}44`, borderRadius:8, padding:"8px 10px" }}>
                          <div style={{ color:C.muted, fontSize:10, marginBottom:4 }}>Avg Response Age</div>
                          <div style={{ color:C.blue, fontSize:24, lineHeight:1, fontWeight:700, fontFamily:"'JetBrains Mono','SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace" }}>{aiAgentHealth.avgRecencySec}s</div>
                          <div style={{ color:C.dim, fontSize:10, marginTop:6 }}>Processing latency</div>
                        </div>
                      </div>
                    </div>

                    <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8 }}>
                      {aiAgentHealth.perAgent.map((a) => (
                        <AgentHealthPlate key={a.id} agent={a} />
                      ))}
                    </div>
                  </Card>

                  <Card glow={C.purple} style={{ marginTop:"auto" }}>
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

                <div style={{ display:"flex", flexDirection:"column", gap:16, height:"100%" }}>
                  <Card glow={C.cyan} style={{ height:"100%", display:"flex", flexDirection:"column" }}>
                    <Label color={C.cyan}>MODEL HEALTH — LIVE / INTEGRATION READY</Label>
                    <div style={{ background:C.surface, border:`1px solid ${C.border}`, borderRadius:6, padding:"8px 10px", marginBottom:10, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                      <div>
                        <div style={{ color:C.muted, fontSize:10 }}>Status</div>
                        <div style={{ color:modelHealthLive ? C.green : C.yellow, fontSize:12, letterSpacing:1 }}>{modelHealth.status}</div>
                      </div>
                      <div style={{ display:"flex", gap:6 }}>
                        <Badge label={`v${modelHealth.modelVersion}`} color={C.purple} />
                        <Badge label={modelHealth.source} color={modelHealthLive ? C.green : C.yellow} />
                      </div>
                    </div>
                    <div style={{ display:"grid", gap:8, flex:1, alignContent:"start" }}>
                      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8 }}>
                        <MetricSparkCard
                          label="Accuracy"
                          value={modelHealth.accuracy}
                          color={C.cyan}
                          series={modelHealthSeries.accuracy}
                        />
                        <MetricSparkCard
                          label="F1 Score"
                          value={modelHealth.f1Score}
                          color={C.blue}
                          series={modelHealthSeries.f1Score}
                        />
                      </div>
                      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8 }}>
                        <DriftGaugeCard value={modelHealth.drift} />
                        <MetricSparkCard
                          label="AUC-ROC"
                          value={modelHealth.auc}
                          color={C.purple}
                          series={modelHealthSeries.auc}
                        />
                      </div>
                      <DriftBarsCard value={modelHealth.drift} />
                    </div>
                    <div style={{ color:C.dim, fontSize:10, lineHeight:1.5, marginTop:10 }}>{modelHealth.note}</div>
                  </Card>
                </div>
              </div>
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

