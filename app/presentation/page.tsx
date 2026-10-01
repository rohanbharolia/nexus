"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { BookOpen, ChevronLeft, ChevronRight, FileText, Keyboard, Maximize, Minimize, Shield, X } from "lucide-react";

// ─── 4 slides only ────────────────────────────────────────────────────────────

const slides = [
  // Slide 0 — Title
  {
    id: "title",
    eyebrow: "HACKATHON 2026",
    title: "NEXUS",
    tagline: "AI-Powered SOC Investigation Platform",
    sub: "From alert to evidence-backed report — in one unified workspace.",
    note: "Nexus is a unified SOC investigation platform that eliminates tool-switching by bringing SIEM, EDR, identity, network, and threat-intel context into a single AI-assisted workflow.",
  },
  // Slide 1 — Identity card
  {
    id: "identity",
    eyebrow: "WHAT IS IT",
    title: "Platform Identity",
    note: "Nexus sits in the Agentic SOC category. It is purpose-built for MSSPs and enterprise security teams who need consistency, auditability, and speed across every investigation.",
    identity: {
      name: "NEXUS",
      problem: "Analysts waste 15+ min per incident switching between disconnected tools, copy-pasting indicators, and writing reports from scratch — introducing errors and losing context.",
      category: "Agentic SOC Platform",
      tags: ["Agentic SOC", "CTI Enrichment", "Threat Hunting", "Vulnerability Triage", "MSSP / Sales Tooling"],
    },
  },
  // Slide 2 — Impact
  {
    id: "impact",
    eyebrow: "WHY IT MATTERS",
    title: "Built for Impact",
    note: "Five capabilities that directly solve the analyst pain. Each one removes a specific friction point that slows down real investigations.",
    impacts: [
      { stat: "15 min+",  label: "Saved per incident",        detail: "Unified workspace eliminates tool-switching" },
      { stat: "10×",      label: "Faster query generation",   detail: "Incident-type-specific queries for Splunk, Falcon, Google SecOps" },
      { stat: "Zero",     label: "Copy-paste errors",         detail: "AI QA catches hostname, IP, and hash mismatches before the report ships" },
      { stat: "AI",       label: "Analysis drafted in seconds", detail: "DeepSeek writes the investigation summary from collected evidence" },
      { stat: "RBAC",     label: "Role-enforced workflow",    detail: "Analyst → Senior → Manager → Admin — every action permission-gated" },
    ],
  },
  // Slide 3 — What's next
  {
    id: "next",
    eyebrow: "WHAT'S NEXT",
    title: "If We Had More Time",
    note: "These are real features that belong in the product. Time and tooling constraints during the hackathon kept them out of this build.",
    nexts: [
      { icon: "🔌", title: "Live Integrations",      detail: "Real Splunk, Falcon, Sentinel, and Entra API calls — not mock adapters" },
      { icon: "🤖", title: "Autonomous Agent Loop",  detail: "AI runs the investigation steps end-to-end, surfaces findings for analyst approval" },
      { icon: "🗺️", title: "Attack Path Visualiser", detail: "Interactive graph of lateral movement across hosts, identities, and networks" },
      { icon: "📡", title: "Live Threat Feeds",       detail: "Real-time IOC ingestion from MISP, OpenCTI, and commercial threat-intel providers" },
      { icon: "📲", title: "Mobile Analyst App",      detail: "Approve reports and receive critical-severity alerts on the go" },
      { icon: "🏢", title: "Multi-Tenant SaaS",       detail: "Isolated client environments with SSO, PostgreSQL, and full audit compliance" },
    ],
  },
];

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function PresentationPage() {
  const [index, setIndex] = useState(0);
  const [showNotes, setShowNotes] = useState(false);
  const [full, setFull] = useState(false);
  const slide = slides[index];

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "ArrowRight" || e.key === " ") { e.preventDefault(); setIndex(i => Math.min(i + 1, slides.length - 1)); }
      else if (e.key === "ArrowLeft") setIndex(i => Math.max(i - 1, 0));
      else if (e.key.toLowerCase() === "n") setShowNotes(v => !v);
      else if (e.key.toLowerCase() === "f") setFull(v => !v);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return (
    <main className={`deck ${full ? "deck-full" : ""}`}>

      {/* Top bar */}
      <header className="deck-top">
        <Link href="/" className="deck-brand">
          <span className="deck-brand-icon"><Shield size={17} /></span>
          <span>NEXUS <small>HACKATHON PRESENTATION</small></span>
        </Link>
        <div className="deck-top-actions">
          <button onClick={() => setShowNotes(v => !v)} title="Toggle speaker notes"><BookOpen size={15} /><span>Notes</span></button>
          <button onClick={() => window.print()} title="Print / PDF"><FileText size={15} /><span>Print</span></button>
          <button onClick={() => setFull(v => !v)}>{full ? <Minimize size={15} /> : <Maximize size={15} />}<span>{full ? "Exit" : "Focus"}</span></button>
        </div>
      </header>

      {/* Slide area */}
      <div className="deck-main">
        <div className="deck-side">
          <span className="deck-index">{String(index + 1).padStart(2, "0")}</span>
          <span className="deck-divider" />
          <span className="deck-total">{String(slides.length).padStart(2, "0")}</span>
          <div className="deck-progress"><i style={{ height: `${(index + 1) / slides.length * 100}%` }} /></div>
        </div>

        <section className="slide slide-new" key={index}>
          {slide.id === "title"    && <TitleSlide s={slide as TitleSlideData} />}
          {slide.id === "identity" && <IdentitySlide s={slide as IdentitySlideData} />}
          {slide.id === "impact"   && <ImpactSlide s={slide as ImpactSlideData} />}
          {slide.id === "next"     && <NextSlide s={slide as NextSlideData} />}
        </section>
      </div>

      {/* Speaker notes */}
      {showNotes && (
        <aside className="speaker-notes">
          <div><BookOpen size={15} /> PRESENTER NOTES <button onClick={() => setShowNotes(false)} aria-label="Close"><X size={15} /></button></div>
          <p>{slide.note}</p>
        </aside>
      )}

      {/* Controls */}
      <footer className="deck-controls">
        <div className="deck-chapter">{slide.eyebrow}</div>
        <div className="deck-controls-center">
          <button disabled={index === 0} onClick={() => setIndex(i => Math.max(0, i - 1))} aria-label="Previous"><ChevronLeft size={19} /></button>
          <span>{index + 1} <i>/</i> {slides.length}</span>
          <button disabled={index === slides.length - 1} onClick={() => setIndex(i => Math.min(slides.length - 1, i + 1))} aria-label="Next"><ChevronRight size={19} /></button>
        </div>
        <div className="deck-shortcuts"><Keyboard size={14} /> ← → navigate · N notes · F focus</div>
      </footer>
    </main>
  );
}

// ─── Slide types ──────────────────────────────────────────────────────────────

type TitleSlideData    = { id: string; eyebrow: string; title: string; tagline: string; sub: string; note: string };
type IdentitySlideData = { id: string; eyebrow: string; title: string; note: string; identity: { name: string; problem: string; category: string; tags: string[] } };
type ImpactSlideData   = { id: string; eyebrow: string; title: string; note: string; impacts: { stat: string; label: string; detail: string }[] };
type NextSlideData     = { id: string; eyebrow: string; title: string; note: string; nexts: { icon: string; title: string; detail: string }[] };

// ─── Slide 0: Title ───────────────────────────────────────────────────────────

function TitleSlide({ s }: { s: TitleSlideData }) {
  return (
    <div className="ns-title">
      <div className="ns-title-left">
        <div className="ns-eyebrow">{s.eyebrow}</div>
        <h1 className="ns-hero">{s.title}</h1>
        <p className="ns-tagline">{s.tagline}</p>
        <p className="ns-sub">{s.sub}</p>
      </div>
      <div className="ns-title-right">
        <div className="ns-glyph">
          <Shield size={80} strokeWidth={1} />
        </div>
        <div className="ns-badge-row">
          {["AI-Powered", "RBAC", "DeepSeek", "OSINT", "Evidence QA"].map(b => (
            <span key={b} className="ns-badge">{b}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Slide 1: Identity ────────────────────────────────────────────────────────

function IdentitySlide({ s }: { s: IdentitySlideData }) {
  return (
    <div className="ns-identity">
      <div className="ns-eyebrow">{s.eyebrow}</div>
      <h1 className="ns-title-text">{s.title}</h1>

      <div className="ns-identity-grid">
        {/* Left — name + category */}
        <div className="ns-id-card">
          <div className="ns-id-name">{s.identity.name}</div>
          <div className="ns-id-cat">{s.identity.category}</div>
          <div className="ns-id-tags">
            {s.identity.tags.map(t => <span key={t} className="ns-badge">{t}</span>)}
          </div>
        </div>

        {/* Right — problem statement */}
        <div className="ns-id-problem">
          <div className="ns-problem-label">THE PROBLEM WE SOLVE</div>
          <p className="ns-problem-text">{s.identity.problem}</p>
        </div>
      </div>
    </div>
  );
}

// ─── Slide 2: Impact ──────────────────────────────────────────────────────────

function ImpactSlide({ s }: { s: ImpactSlideData }) {
  return (
    <div className="ns-impact">
      <div className="ns-eyebrow">{s.eyebrow}</div>
      <h1 className="ns-title-text">{s.title}</h1>
      <div className="ns-impact-grid">
        {s.impacts.map(item => (
          <div key={item.stat} className="ns-impact-card">
            <div className="ns-impact-stat">{item.stat}</div>
            <div className="ns-impact-label">{item.label}</div>
            <div className="ns-impact-detail">{item.detail}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Slide 3: What's Next ────────────────────────────────────────────────────

function NextSlide({ s }: { s: NextSlideData }) {
  return (
    <div className="ns-next">
      <div className="ns-eyebrow">{s.eyebrow}</div>
      <h1 className="ns-title-text">{s.title}</h1>
      <div className="ns-next-grid">
        {s.nexts.map(item => (
          <div key={item.title} className="ns-next-card">
            <span className="ns-next-icon">{item.icon}</span>
            <b>{item.title}</b>
            <p>{item.detail}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
