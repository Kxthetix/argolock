import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, ArrowRight, Activity, Terminal, Cpu, CheckCircle2,
  Lock, Zap, Server, ChevronRight, FileText, Layers, Crosshair
} from 'lucide-react';

export function LandingPage() {
  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div style={{
      background: '#04040d',
      color: '#ffffff',
      fontFamily: "'Outfit', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
      minHeight: '100vh',
      overflowX: 'hidden',
      scrollBehavior: 'smooth',
      position: 'relative',
    }}>
      {/* ── Dynamic Styles & Animations ── */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Outfit:wght@400;500;600;700;800;900&display=swap');

        .glow-button {
          transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .glow-button:hover {
          transform: translateY(-2px);
          box-shadow: 0 0 25px rgba(99, 102, 241, 0.5);
          opacity: 0.95;
        }
        .feature-card {
          transition: all 0.3s ease;
        }
        .feature-card:hover {
          transform: translateY(-6px);
          border-color: rgba(99, 102, 241, 0.4) !important;
          background: rgba(15, 15, 35, 0.75) !important;
          box-shadow: 0 12px 35px rgba(99, 102, 241, 0.12);
        }
        .pricing-card {
          transition: all 0.3s ease;
        }
        .pricing-card:hover {
          transform: scale(1.02);
          border-color: rgba(168, 85, 247, 0.4) !important;
          box-shadow: 0 15px 35px rgba(168, 85, 247, 0.12);
        }
        .pulse-dot {
          animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.4; transform: scale(0.9); }
        }
      `}</style>

      {/* ── Background Glowing Ambient Lights ── */}
      <div style={{
        position: 'absolute',
        width: '800px',
        height: '800px',
        background: 'radial-gradient(circle, rgba(99,102,241,0.09) 0%, rgba(99,102,241,0) 70%)',
        top: '-10%',
        left: '-10%',
        borderRadius: '50%',
        filter: 'blur(90px)',
        pointerEvents: 'none',
        zIndex: 1,
      }} />
      <div style={{
        position: 'absolute',
        width: '900px',
        height: '900px',
        background: 'radial-gradient(circle, rgba(168,85,247,0.06) 0%, rgba(168,85,247,0) 70%)',
        bottom: '15%',
        right: '-10%',
        borderRadius: '50%',
        filter: 'blur(100px)',
        pointerEvents: 'none',
        zIndex: 1,
      }} />

      {/* ── NAVIGATION BAR ── */}
      <header style={{
        position: 'sticky',
        top: 0,
        background: 'rgba(4, 4, 13, 0.8)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
        zIndex: 100,
        padding: '16px 40px',
      }}>
        <div style={{
          maxWidth: '1240px',
          margin: '0 auto',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          {/* Logo */}
          <Link to="/" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(168, 85, 247, 0.2))',
              border: '1px solid rgba(99, 102, 241, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Shield style={{ width: 20, height: 20, color: '#00d4ff' }} />
            </div>
            <span style={{
              fontSize: '22px',
              fontWeight: 900,
              letterSpacing: '-0.5px',
              background: 'linear-gradient(135deg, #fff 30%, #a855f7 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}>
              ArgoLock
            </span>
          </Link>

          {/* Links */}
          <nav style={{ display: 'flex', alignItems: 'center', gap: '32px' }}>
            <button
              onClick={() => scrollToSection('idea')}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.7)', cursor: 'pointer', fontSize: '14px', fontWeight: 500 }}
            >
              The Idea
            </button>
            <button
              onClick={() => scrollToSection('features')}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.7)', cursor: 'pointer', fontSize: '14px', fontWeight: 500 }}
            >
              Workflow
            </button>
            <button
              onClick={() => scrollToSection('pricing')}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.7)', cursor: 'pointer', fontSize: '14px', fontWeight: 500 }}
            >
              Plans
            </button>

            <Link
              to="/dashboard"
              className="glow-button"
              style={{
                textDecoration: 'none',
                background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
                borderRadius: '8px',
                padding: '9px 20px',
                color: '#fff',
                fontSize: '13px',
                fontWeight: 700,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                boxShadow: '0 4px 15px rgba(99, 102, 241, 0.35)',
              }}
            >
              Launch Platform
              <ArrowRight style={{ width: 14, height: 14 }} />
            </Link>
          </nav>
        </div>
      </header>

      {/* ── HERO SECTION ── */}
      <section style={{
        maxWidth: '1240px',
        margin: '0 auto',
        padding: '100px 40px 80px',
        position: 'relative',
        zIndex: 2,
        display: 'grid',
        gridTemplateColumns: '1.2fr 1fr',
        gap: '60px',
        alignItems: 'center',
      }}>
        {/* Left Column: Pitch & Action */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div style={{
            alignSelf: 'start',
            background: 'linear-gradient(90deg, rgba(99,102,241,0.15) 0%, rgba(168,85,247,0.15) 100%)',
            border: '1px solid rgba(168,85,247,0.3)',
            borderRadius: '100px',
            padding: '6px 16px',
            fontSize: '12px',
            fontWeight: 600,
            color: '#c084fc',
            letterSpacing: '0.5px',
            textTransform: 'uppercase',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
          }}>
            <span className="pulse-dot" style={{ width: 8, height: 8, borderRadius: '50%', background: '#34c759' }} />
            Production-Grade Autonomous VAPT
          </div>

          <h1 style={{
            fontSize: '52px',
            fontWeight: 900,
            lineHeight: 1.1,
            letterSpacing: '-1.8px',
            background: 'linear-gradient(135deg, #ffffff 30%, #d8b4fe 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}>
            Autonomous Pentesting & AI Remediation for Modern SaaS
          </h1>

          <p style={{
            fontSize: '16px',
            color: 'rgba(255,255,255,0.65)',
            lineHeight: 1.65,
            maxWidth: '540px',
          }}>
            ArgoLock deploys autonomous multi-agent security pipelines that discover attack surfaces, confirm real-world exploitability through safe sandbox probes, and generate precision code fixes.
          </p>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', marginTop: '8px' }}>
            <Link
              to="/dashboard"
              className="glow-button"
              style={{
                textDecoration: 'none',
                background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
                borderRadius: '10px',
                padding: '14px 30px',
                color: '#fff',
                fontSize: '15px',
                fontWeight: 700,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '10px',
                boxShadow: '0 4px 25px rgba(99, 102, 241, 0.4)',
              }}
            >
              <span>Launch Platform</span>
              <ArrowRight style={{ width: 16, height: 16 }} />
            </Link>

            <Link
              to="/scans"
              style={{
                textDecoration: 'none',
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(255,255,255,0.15)',
                borderRadius: '10px',
                padding: '14px 26px',
                color: 'rgba(255,255,255,0.9)',
                fontSize: '15px',
                fontWeight: 600,
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <Crosshair style={{ width: 16, height: 16, color: '#00d4ff' }} />
              <span>Run Live Scan</span>
            </Link>
          </div>

          {/* Quick Metrics Strip */}
          <div style={{
            display: 'flex',
            gap: '32px',
            marginTop: '16px',
            paddingTop: '24px',
            borderTop: '1px solid rgba(255, 255, 255, 0.06)',
          }}>
            <div>
              <div style={{ fontSize: '20px', fontWeight: 900, color: '#fff' }}>6 Agents</div>
              <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.45)', marginTop: 2 }}>Autonomous LLM Engine</div>
            </div>
            <div>
              <div style={{ fontSize: '20px', fontWeight: 900, color: '#00d4ff' }}>9 Scanners</div>
              <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.45)', marginTop: 2 }}>Integrated Tool Registry</div>
            </div>
            <div>
              <div style={{ fontSize: '20px', fontWeight: 900, color: '#34c759' }}>0 Auth Gate</div>
              <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.45)', marginTop: 2 }}>Instant Console Access</div>
            </div>
          </div>
        </div>

        {/* Right Column: Interactive Console Preview Card */}
        <div style={{
          background: 'rgba(12, 13, 30, 0.65)',
          border: '1px solid rgba(99, 102, 241, 0.3)',
          borderRadius: '24px',
          padding: '36px',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.5), 0 0 50px rgba(99, 102, 241, 0.08)',
          display: 'flex',
          flexDirection: 'column',
          gap: '24px',
        }}>
          {/* Card Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Terminal style={{ width: 20, height: 20, color: '#818cf8' }} />
              <span style={{ fontSize: '15px', fontWeight: 800, letterSpacing: '-0.2px' }}>ArgoLock Console</span>
            </div>
            <div style={{
              background: 'rgba(52, 199, 89, 0.1)',
              border: '1px solid rgba(52, 199, 89, 0.3)',
              borderRadius: '100px',
              padding: '4px 12px',
              fontSize: '11px',
              fontWeight: 700,
              color: '#34c759',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}>
              <span className="pulse-dot" style={{ width: 6, height: 6, borderRadius: '50%', background: '#34c759' }} />
              OPERATIONAL
            </div>
          </div>

          {/* Pipeline Live Status Rows */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {[
              { phase: '1. Reconnaissance', tool: 'Subfinder + Nmap + WhatWeb', status: 'Ready', color: '#00d4ff' },
              { phase: '2. Vulnerability Scan', tool: 'Nuclei + OWASP ZAP + Dalfox', status: 'Armed', color: '#818cf8' },
              { phase: '3. Safe Exploitation', tool: 'ExploitAgent Non-Destructive Sandbox', status: 'Active', color: '#a855f7' },
              { phase: '4. AI Remediation', tool: 'Claude 3.5 Sonnet / GPT-4o Fix Engine', status: 'Online', color: '#34c759' },
            ].map((item, idx) => (
              <div key={idx} style={{
                background: 'rgba(255, 255, 255, 0.02)',
                border: '1px solid rgba(255, 255, 255, 0.06)',
                borderRadius: '12px',
                padding: '12px 16px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}>
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 700, color: '#fff' }}>{item.phase}</div>
                  <div style={{ fontSize: '11px', color: 'rgba(255,255,255,0.45)', marginTop: '2px' }}>{item.tool}</div>
                </div>
                <span style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  color: item.color,
                  background: 'rgba(255,255,255,0.03)',
                  border: `1px solid ${item.color}40`,
                  padding: '3px 10px',
                  borderRadius: '100px',
                }}>
                  {item.status}
                </span>
              </div>
            ))}
          </div>

          {/* Console Action Button */}
          <Link
            to="/dashboard"
            className="glow-button"
            style={{
              textDecoration: 'none',
              background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
              borderRadius: '10px',
              padding: '14px',
              color: '#fff',
              fontSize: '14px',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              boxShadow: '0 4px 20px rgba(99, 102, 241, 0.3)',
            }}
          >
            <span>Enter Platform Console</span>
            <ArrowRight style={{ width: 16, height: 16 }} />
          </Link>

          {/* Sub-links */}
          <div style={{ display: 'flex', justifyContent: 'space-around', fontSize: '12px', color: 'rgba(255,255,255,0.5)' }}>
            <Link to="/agents" style={{ color: 'rgba(255,255,255,0.6)', textDecoration: 'none' }}>
              Specialized AI Agents →
            </Link>
            <Link to="/tool-status" style={{ color: 'rgba(255,255,255,0.6)', textDecoration: 'none' }}>
              Tool Health & Status →
            </Link>
          </div>
        </div>
      </section>

      {/* ── THE IDEA SECTION ── */}
      <section id="idea" style={{
        background: 'rgba(10, 10, 25, 0.5)',
        borderTop: '1px solid rgba(255, 255, 255, 0.04)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
        padding: '80px 40px',
      }}>
        <div style={{ maxWidth: '1240px', margin: '0 auto', display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: '60px', alignItems: 'center' }}>
          <div>
            <h2 style={{ fontSize: '36px', fontWeight: 800, letterSpacing: '-1.2px', marginBottom: '16px' }}>
              The VAPT Philosophy: <br />
              Proof, Not Guesswork
            </h2>
            <p style={{ fontSize: '15px', color: 'rgba(255,255,255,0.65)', lineHeight: 1.7, marginBottom: '20px' }}>
              Traditional vulnerability scanners produce huge lists of unvalidated CVE references, wasting hours on false positives. ArgoLock redesigns this workflow with strict evidence validation.
            </p>
            <blockquote style={{
              borderLeft: '4px solid #a855f7',
              paddingLeft: '16px',
              fontStyle: 'italic',
              color: '#d8b4fe',
              fontSize: '14px',
              margin: '20px 0',
            }}>
              "If it cannot be safely verified in a non-destructive sandbox, it is not a confirmed finding. We test, verify, score CVSS, and generate remediation code."
            </blockquote>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', gap: '16px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '14px', padding: '24px' }}>
              <span style={{ fontSize: '28px' }}>🤖</span>
              <div>
                <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff', marginBottom: '6px' }}>Autonomous AI Agents</h3>
                <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', lineHeight: 1.6 }}>
                  Specialized agents parse scanner outputs, compute explainable CVSS scores, map findings to OWASP Top 10 categories, and generate ready-to-merge secure patches.
                </p>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '16px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '14px', padding: '24px' }}>
              <span style={{ fontSize: '28px' }}>⚡</span>
              <div>
                <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff', marginBottom: '6px' }}>Zero-Friction Access</h3>
                <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', lineHeight: 1.6 }}>
                  Direct console access without authentication barriers or token expiry blockers. Run scans, view real-time WebSocket progress, and export executive PDF reports instantly.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── WORKFLOW FEATURES SECTION ── */}
      <section id="features" style={{
        maxWidth: '1240px',
        margin: '0 auto',
        padding: '90px 40px',
      }}>
        <div style={{ textAlign: 'center', marginBottom: '60px' }}>
          <h2 style={{ fontSize: '36px', fontWeight: 800, letterSpacing: '-1px' }}>Core Automated Workflow</h2>
          <p style={{ fontSize: '15px', color: 'rgba(255,255,255,0.5)', marginTop: '8px' }}>
            Four orchestrated security phases executed across sandboxed scanner workers.
          </p>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
          gap: '24px',
        }}>
          {/* Recon */}
          <div className="feature-card" style={{
            background: 'rgba(13, 13, 31, 0.35)',
            border: '1px solid rgba(255, 255, 255, 0.06)',
            borderRadius: '18px',
            padding: '32px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
          }}>
            <div style={{ width: 48, height: 48, borderRadius: 12, background: 'rgba(0, 212, 255, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid rgba(0, 212, 255, 0.2)' }}>
              <Crosshair style={{ width: 24, height: 24, color: '#00d4ff' }} />
            </div>
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff' }}>1. Asset Recon</h3>
            <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.55)', lineHeight: 1.6 }}>
              Automated OSINT asset discovery, subdomain mapping, and open port identification via Subfinder, Amass, and unprivileged Nmap probes.
            </p>
          </div>

          {/* Scanning */}
          <div className="feature-card" style={{
            background: 'rgba(13, 13, 31, 0.35)',
            border: '1px solid rgba(255, 255, 255, 0.06)',
            borderRadius: '18px',
            padding: '32px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
          }}>
            <div style={{ width: 48, height: 48, borderRadius: 12, background: 'rgba(99, 102, 241, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid rgba(99, 102, 241, 0.2)' }}>
              <Activity style={{ width: 24, height: 24, color: '#818cf8' }} />
            </div>
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff' }}>2. Vuln Scanning</h3>
            <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.55)', lineHeight: 1.6 }}>
              Triggers Nuclei template engines, Nikto HTTP analyzers, Dalfox XSS probes, and active OWASP ZAP scanning adapters.
            </p>
          </div>

          {/* Exploitation */}
          <div className="feature-card" style={{
            background: 'rgba(13, 13, 31, 0.35)',
            border: '1px solid rgba(255, 255, 255, 0.06)',
            borderRadius: '18px',
            padding: '32px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
          }}>
            <div style={{ width: 48, height: 48, borderRadius: 12, background: 'rgba(168, 85, 247, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid rgba(168, 85, 247, 0.2)' }}>
              <Zap style={{ width: 24, height: 24, color: '#c084fc' }} />
            </div>
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff' }}>3. Safe Exploit</h3>
            <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.55)', lineHeight: 1.6 }}>
              ExploitAgent runs active, non-destructive safety checks to confirm exploitability, generate evidence proofs, and eliminate false alarms.
            </p>
          </div>

          {/* Reporting */}
          <div className="feature-card" style={{
            background: 'rgba(13, 13, 31, 0.35)',
            border: '1px solid rgba(255, 255, 255, 0.06)',
            borderRadius: '18px',
            padding: '32px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
          }}>
            <div style={{ width: 48, height: 48, borderRadius: 12, background: 'rgba(52, 199, 89, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid rgba(52, 199, 89, 0.2)' }}>
              <FileText style={{ width: 24, height: 24, color: '#34c759' }} />
            </div>
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff' }}>4. Reports & Remediation</h3>
            <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.55)', lineHeight: 1.6 }}>
              Executive summaries, CVSS score vectors, and AI-authored code patches exported into standalone, auditor-ready PDF reports.
            </p>
          </div>
        </div>
      </section>

      {/* ── SUBSCRIPTIONS / TIERS SECTION ── */}
      <section id="pricing" style={{
        background: 'rgba(10, 10, 25, 0.5)',
        borderTop: '1px solid rgba(255, 255, 255, 0.04)',
        padding: '90px 40px 110px',
      }}>
        <div style={{ maxWidth: '1240px', margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: '60px' }}>
            <h2 style={{ fontSize: '36px', fontWeight: 800, letterSpacing: '-1px' }}>Flexible Subscriptions</h2>
            <p style={{ fontSize: '15px', color: 'rgba(255,255,255,0.5)', marginTop: '8px' }}>
              Choose a VAPT scale tailored to your organization.
            </p>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
            gap: '30px',
            maxWidth: '1060px',
            margin: '0 auto',
          }}>
            {/* Community Tier */}
            <div className="pricing-card" style={{
              background: 'rgba(13, 13, 31, 0.45)',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: '20px',
              padding: '40px',
              display: 'flex',
              flexDirection: 'column',
              gap: '24px',
            }}>
              <div>
                <h3 style={{ fontSize: '20px', fontWeight: 800, color: '#fff' }}>Community</h3>
                <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', marginTop: '4px' }}>For indie devs & individual researchers</p>
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px' }}>
                <span style={{ fontSize: '40px', fontWeight: 900, color: '#fff' }}>$0</span>
                <span style={{ fontSize: '13px', color: 'rgba(255,255,255,0.4)' }}>/ forever</span>
              </div>
              <ul style={{ display: 'flex', flexDirection: 'column', gap: '14px', padding: 0, margin: 0, listStyle: 'none', fontSize: '13px', color: 'rgba(255,255,255,0.7)' }}>
                <li>✓ Unlimited unauthenticated scanning</li>
                <li>✓ Full 9-tool automated pipeline</li>
                <li>✓ Real-time WebSocket terminal tracking</li>
                <li>✓ AI vulnerability classification</li>
                <li>✓ Downloadable JSON & PDF reports</li>
              </ul>
              <Link
                to="/dashboard"
                style={{
                  textDecoration: 'none',
                  textAlign: 'center',
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.15)',
                  borderRadius: '10px',
                  padding: '12px',
                  color: '#fff',
                  fontSize: '14px',
                  fontWeight: 600,
                  marginTop: 'auto',
                }}
              >
                Launch Community
              </Link>
            </div>

            {/* Pro Tier */}
            <div className="pricing-card" style={{
              background: 'rgba(13, 13, 31, 0.7)',
              border: '1px solid rgba(99, 102, 241, 0.5)',
              borderRadius: '20px',
              padding: '40px',
              display: 'flex',
              flexDirection: 'column',
              gap: '24px',
              position: 'relative',
            }}>
              <div style={{
                position: 'absolute',
                top: '-12px',
                right: '24px',
                background: 'linear-gradient(135deg, #a855f7 0%, #6366f1 100%)',
                color: '#fff',
                fontSize: '11px',
                fontWeight: 800,
                textTransform: 'uppercase',
                padding: '4px 14px',
                borderRadius: '100px',
                letterSpacing: '0.5px',
              }}>
                POPULAR
              </div>
              <div>
                <h3 style={{ fontSize: '20px', fontWeight: 800, color: '#fff' }}>Professional</h3>
                <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', marginTop: '4px' }}>For growth SaaS & security teams</p>
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px' }}>
                <span style={{ fontSize: '40px', fontWeight: 900, color: '#fff' }}>$99</span>
                <span style={{ fontSize: '13px', color: 'rgba(255,255,255,0.4)' }}>/ month</span>
              </div>
              <ul style={{ display: 'flex', flexDirection: 'column', gap: '14px', padding: 0, margin: 0, listStyle: 'none', fontSize: '13px', color: 'rgba(255,255,255,0.7)' }}>
                <li>✓ Parallel scan pipeline execution</li>
                <li>✓ Deep port scan (real Nmap connect engine)</li>
                <li>✓ Full MITRE ATT&CK & Cyber Kill Chain mapping</li>
                <li>✓ AI remediation code patches (Python, JS, Go)</li>
                <li>✓ Evidence collector with SHA-256 integrity</li>
              </ul>
              <Link
                to="/dashboard"
                className="glow-button"
                style={{
                  textDecoration: 'none',
                  textAlign: 'center',
                  background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
                  borderRadius: '10px',
                  padding: '12px',
                  color: '#fff',
                  fontSize: '14px',
                  fontWeight: 700,
                  boxShadow: '0 4px 20px rgba(99, 102, 241, 0.35)',
                  marginTop: 'auto',
                }}
              >
                Open Pro Console
              </Link>
            </div>

            {/* Enterprise Tier */}
            <div className="pricing-card" style={{
              background: 'rgba(13, 13, 31, 0.45)',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              borderRadius: '20px',
              padding: '40px',
              display: 'flex',
              flexDirection: 'column',
              gap: '24px',
            }}>
              <div>
                <h3 style={{ fontSize: '20px', fontWeight: 800, color: '#fff' }}>Enterprise</h3>
                <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', marginTop: '4px' }}>For enterprise security operations</p>
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px' }}>
                <span style={{ fontSize: '40px', fontWeight: 900, color: '#fff' }}>$499</span>
                <span style={{ fontSize: '13px', color: 'rgba(255,255,255,0.4)' }}>/ month</span>
              </div>
              <ul style={{ display: 'flex', flexDirection: 'column', gap: '14px', padding: 0, margin: 0, listStyle: 'none', fontSize: '13px', color: 'rgba(255,255,255,0.7)' }}>
                <li>✓ Custom exploitation playbooks</li>
                <li>✓ Dedicated scanner runner containers</li>
                <li>✓ CI/CD security gating webhook API</li>
                <li>✓ Multi-target continuous attack surface audit</li>
                <li>✓ 24/7 dedicated engineering support</li>
              </ul>
              <Link
                to="/dashboard"
                style={{
                  textDecoration: 'none',
                  textAlign: 'center',
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.15)',
                  borderRadius: '10px',
                  padding: '12px',
                  color: '#fff',
                  fontSize: '14px',
                  fontWeight: 600,
                  marginTop: 'auto',
                }}
              >
                Access Enterprise
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ── FOOTER ── */}
      <footer style={{
        background: '#020208',
        borderTop: '1px solid rgba(255, 255, 255, 0.04)',
        padding: '40px 40px',
        fontSize: '13px',
        color: 'rgba(255,255,255,0.45)',
      }}>
        <div style={{ maxWidth: '1240px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>© {new Date().getFullYear()} ArgoLock VAPT Platform. Autonomous Cybersecurity.</div>
          <div style={{ display: 'flex', gap: '24px' }}>
            <Link to="/dashboard" style={{ color: 'rgba(255,255,255,0.6)', textDecoration: 'none' }}>
              Dashboard
            </Link>
            <Link to="/scans" style={{ color: 'rgba(255,255,255,0.6)', textDecoration: 'none' }}>
              Scans
            </Link>
            <Link to="/reports" style={{ color: 'rgba(255,255,255,0.6)', textDecoration: 'none' }}>
              Reports
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
