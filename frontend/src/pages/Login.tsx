import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { IS_DEMO, API_BASE } from '../lib/api';

export function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSignUp, setIsSignUp] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const navigate = useNavigate();

  // Redirect to dashboard if already logged in
  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      navigate('/');
    }
  }, [navigate]);

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;

    if (password.length < 6) {
      setError('Password must be at least 6 characters long');
      return;
    }

    setLoading(true);
    setError('');
    setSuccessMsg('');

    if (IS_DEMO) {
      // Simulate auth locally for standalone static builds
      setTimeout(() => {
        localStorage.setItem('auth_token', 'mock-demo-jwt-token');
        localStorage.setItem('auth_email', email);
        window.location.href = '/';
      }, 600);
      return;
    }

    try {
      const endpoint = `${API_BASE}/auth/login`;
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      let data: any = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        throw new Error(`Server error (${response.status}): Invalid response format`);
      }

      if (!response.ok) {
        throw new Error(data.detail || 'Authentication failed');
      }

      // Save credentials
      localStorage.setItem('auth_token', data.access_token);
      localStorage.setItem('auth_email', data.email);

      // Redirect
      window.location.href = '/';
    } catch (err: any) {
      setError(err.message || 'An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

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
      fontFamily: "'Outfit', 'Inter', sans-serif",
      minHeight: '100vh',
      overflowX: 'hidden',
      scrollBehavior: 'smooth',
      position: 'relative',
    }}>
      {/* ── Dynamic Google Fonts Load ── */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Outfit:wght@400;500;600;700;800;900&display=swap');
        
        .glow-button {
          transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .glow-button:hover {
          transform: translateY(-2px);
          box-shadow: 0 0 20px rgba(99, 102, 241, 0.4);
          opacity: 0.95;
        }
        .feature-card {
          transition: all 0.3s ease;
        }
        .feature-card:hover {
          transform: translateY(-5px);
          border-color: rgba(99, 102, 241, 0.4) !important;
          background: rgba(13, 13, 31, 0.6) !important;
          box-shadow: 0 10px 30px rgba(99, 102, 241, 0.05);
        }
        .pricing-card {
          transition: all 0.3s ease;
        }
        .pricing-card:hover {
          transform: scale(1.02);
          border-color: rgba(168, 85, 247, 0.4) !important;
          box-shadow: 0 15px 35px rgba(168, 85, 247, 0.1);
        }
      `}</style>

      {/* ── Background Glowing Blurs ── */}
      <div style={{
        position: 'absolute',
        width: '800px',
        height: '800px',
        background: 'radial-gradient(circle, rgba(99,102,241,0.08) 0%, rgba(99,102,241,0) 70%)',
        top: '-10%',
        left: '-10%',
        borderRadius: '50%',
        filter: 'blur(80px)',
        pointerEvents: 'none',
        zIndex: 1,
      }} />
      <div style={{
        position: 'absolute',
        width: '900px',
        height: '900px',
        background: 'radial-gradient(circle, rgba(168,85,247,0.05) 0%, rgba(168,85,247,0) 70%)',
        bottom: '20%',
        right: '-10%',
        borderRadius: '50%',
        filter: 'blur(90px)',
        pointerEvents: 'none',
        zIndex: 1,
      }} />

      {/* ── NAVIGATION BAR ── */}
      <header style={{
        position: 'sticky',
        top: 0,
        background: 'rgba(4, 4, 13, 0.7)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
        zIndex: 100,
        padding: '16px 40px',
      }}>
        <div style={{
          maxWidth: '1200px',
          margin: '0 auto',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'between',
        }}>
          {/* Logo */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1 }}>
            <span style={{ fontSize: '24px' }}>🛡️</span>
            <span style={{
              fontSize: '20px',
              fontWeight: 800,
              letterSpacing: '-0.5px',
              background: 'linear-gradient(135deg, #fff 0%, #a855f7 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}>
              ArgoLock
            </span>
          </div>

          {/* Links */}
          <nav style={{ display: 'flex', alignItems: 'center', gap: '30px' }}>
            <button 
              onClick={() => scrollToSection('idea')}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.6)', cursor: 'pointer', fontSize: '14px', fontWeight: 500 }}
            >
              The Idea
            </button>
            <button 
              onClick={() => scrollToSection('features')}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.6)', cursor: 'pointer', fontSize: '14px', fontWeight: 500 }}
            >
              Features
            </button>
            <button 
              onClick={() => scrollToSection('pricing')}
              style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.6)', cursor: 'pointer', fontSize: '14px', fontWeight: 500 }}
            >
              Subscription
            </button>
            
            <button 
              onClick={() => scrollToSection('portal')}
              className="glow-button"
              style={{
                background: 'rgba(99,102,241,0.1)',
                border: '1px solid rgba(99,102,241,0.4)',
                borderRadius: '8px',
                padding: '8px 18px',
                color: '#818cf8',
                fontSize: '13px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Launch Portal
            </button>
          </nav>
        </div>
      </header>

      {/* ── HERO & AUTH PORTAL SECTION ── */}
      <section id="portal" style={{
        maxWidth: '1200px',
        margin: '0 auto',
        padding: '80px 40px',
        position: 'relative',
        zIndex: 10,
        display: 'grid',
        gridTemplateColumns: '1.2fr 0.8fr',
        gap: '60px',
        alignItems: 'center',
      }}>
        {/* Pitch / Idea Column */}
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
          }}>
            🛡️ AI-Powered Vulnerability Scanner
          </div>
          
          <h1 style={{
            fontSize: '48px',
            fontWeight: 900,
            lineHeight: 1.15,
            letterSpacing: '-1.5px',
            background: 'linear-gradient(135deg, #ffffff 0%, #d8b4fe 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}>
            Next-Generation <br />
            Autonomous VAPT <br />
            for Modern SaaS
          </h1>

          <p style={{
            fontSize: '16px',
            color: 'rgba(255,255,255,0.6)',
            lineHeight: 1.6,
            maxWidth: '520px',
          }}>
            ArgoLock deploys autonomous security agents that execute comprehensive reconnaissance, detect deep application flaws, and run automated, safe exploit proofs of concept. Get verified security audits and clean PDF reports in minutes.
          </p>

          <div style={{ display: 'flex', gap: '16px', marginTop: '12px' }}>
            <button
              onClick={() => scrollToSection('portal')}
              className="glow-button"
              style={{
                background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
                border: 'none',
                borderRadius: '8px',
                padding: '14px 28px',
                color: '#fff',
                fontSize: '14px',
                fontWeight: 600,
                cursor: 'pointer',
                boxShadow: '0 4px 20px rgba(99, 102, 241, 0.3)',
              }}
            >
              Start Free Scan
            </button>
            <button
              onClick={() => scrollToSection('idea')}
              className="glow-button"
              style={{
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '8px',
                padding: '14px 28px',
                color: 'rgba(255,255,255,0.8)',
                fontSize: '14px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Explore Features
            </button>
          </div>
        </div>

        {/* Auth Column */}
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <div style={{
            width: '100%',
            maxWidth: '400px',
            background: 'rgba(13, 13, 31, 0.45)',
            border: '1px solid rgba(99, 102, 241, 0.25)',
            borderRadius: '20px',
            padding: '36px',
            backdropFilter: 'blur(20px)',
            WebkitBackdropFilter: 'blur(20px)',
            boxShadow: '0 10px 40px rgba(0, 0, 0, 0.4), 0 0 40px rgba(99, 102, 241, 0.05)',
            display: 'flex',
            flexDirection: 'column',
            gap: '24px',
          }}>
            {/* Header / Toggle */}
            <div style={{ textAlign: 'center' }}>
              <div style={{
                display: 'inline-flex',
                background: 'rgba(5, 5, 16, 0.5)',
                border: '1px solid rgba(255,255,255,0.05)',
                borderRadius: '100px',
                padding: '4px',
                marginBottom: '16px',
              }}>
                <button
                  onClick={() => { setIsSignUp(false); setError(''); }}
                  style={{
                    background: !isSignUp ? 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)' : 'none',
                    border: 'none',
                    borderRadius: '100px',
                    padding: '8px 24px',
                    color: !isSignUp ? '#fff' : 'rgba(255,255,255,0.5)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                  }}
                >
                  Log In
                </button>
                <button
                  onClick={() => { setIsSignUp(true); setError(''); }}
                  style={{
                    background: isSignUp ? 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)' : 'none',
                    border: 'none',
                    borderRadius: '100px',
                    padding: '8px 24px',
                    color: isSignUp ? '#fff' : 'rgba(255,255,255,0.5)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                  }}
                >
                  Sign Up
                </button>
              </div>

              <h2 style={{ fontSize: '18px', fontWeight: 800, color: '#fff', letterSpacing: '-0.3px' }}>
                {isSignUp ? 'Create Security Account' : 'Security Portal Access'}
              </h2>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px', opacity: 0.6 }}>
                {isSignUp ? 'Register to manage assets & scan queues' : 'Sign in to run scans & generate reports'}
              </p>
            </div>

            {/* Auth Form */}
            <form onSubmit={handleAuth} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <label style={{ fontSize: '11px', fontWeight: 600, color: 'rgba(255,255,255,0.7)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Email Address
                </label>
                <input
                  type="email"
                  required
                  placeholder="name@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(5, 5, 16, 0.6)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '8px',
                    padding: '12px 14px',
                    color: '#fff',
                    fontSize: '13px',
                    outline: 'none',
                    transition: 'border-color 0.2s',
                  }}
                  onFocus={(e) => { e.target.style.borderColor = '#6366f1'; }}
                  onBlur={(e) => { e.target.style.borderColor = 'rgba(255, 255, 255, 0.1)'; }}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <label style={{ fontSize: '11px', fontWeight: 600, color: 'rgba(255,255,255,0.7)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Password
                </label>
                <input
                  type="password"
                  required
                  minLength={6}
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{
                    width: '100%',
                    background: 'rgba(5, 5, 16, 0.6)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '8px',
                    padding: '12px 14px',
                    color: '#fff',
                    fontSize: '13px',
                    outline: 'none',
                    transition: 'border-color 0.2s',
                  }}
                  onFocus={(e) => { e.target.style.borderColor = '#6366f1'; }}
                  onBlur={(e) => { e.target.style.borderColor = 'rgba(255, 255, 255, 0.1)'; }}
                />
              </div>

              {IS_DEMO && (
                <div style={{
                  background: 'rgba(99, 102, 241, 0.08)',
                  border: '1px dashed rgba(99, 102, 241, 0.25)',
                  borderRadius: '8px',
                  padding: '10px',
                  textAlign: 'center',
                  fontSize: '11px',
                  color: '#818cf8',
                }}>
                  💡 <strong>Demo Instance:</strong> Any mock email and a 6+ char password will bypass authentication.
                </div>
              )}

              {error && (
                <div style={{
                  background: 'rgba(255, 59, 48, 0.08)',
                  border: '1px solid rgba(255, 59, 48, 0.2)',
                  borderRadius: '8px',
                  padding: '10px',
                  color: '#ff453a',
                  fontSize: '11px',
                }}>
                  ⚠️ {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="glow-button"
                style={{
                  width: '100%',
                  background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
                  border: 'none',
                  borderRadius: '8px',
                  padding: '12px',
                  color: '#fff',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: loading ? 'not-allowed' : 'pointer',
                  boxShadow: '0 4px 15px rgba(99, 102, 241, 0.2)',
                }}
              >
                {loading ? 'Authenticating...' : isSignUp ? 'Create Account' : 'Enter Portal'}
              </button>
            </form>
          </div>
        </div>
      </section>

      {/* ── THE IDEA SECTION ── */}
      <section id="idea" style={{
        background: 'rgba(10, 10, 25, 0.5)',
        borderTop: '1px solid rgba(255, 255, 255, 0.03)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.03)',
        padding: '80px 40px',
      }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: '60px', alignItems: 'center' }}>
          <div>
            <h2 style={{ fontSize: '32px', fontWeight: 800, letterSpacing: '-1px', marginBottom: '16px' }}>
              The VAPT Idea: <br />
              Validation, Not Guesswork
            </h2>
            <p style={{ fontSize: '15px', color: 'rgba(255,255,255,0.6)', lineHeight: 1.7, marginBottom: '20px' }}>
              Traditional scanners overwhelm security teams with hundreds of false positives. ArgoLock redesigns this workflow by combining passive OSINT, active service analysis, and a secure multi-stage exploitation sandbox.
            </p>
            <blockquote style={{
              borderLeft: '4px solid #a855f7',
              paddingLeft: '16px',
              fontStyle: 'italic',
              color: '#d8b4fe',
              fontSize: '14px',
              margin: '20px 0',
            }}>
              "If it cannot be securely exploited under safe constraints, it is not a validated finding. We test, we prove, we report."
            </blockquote>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', gap: '16px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '12px', padding: '20px' }}>
              <span style={{ fontSize: '28px' }}>🤖</span>
              <div>
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#fff', marginBottom: '6px' }}>AI-Driven Remediations</h3>
                <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', lineHeight: 1.5 }}>
                  AI Agents scan validated findings, map them directly to OWASP compliance headers, explain the root cause, and draft complete secure code patches (Python, JS, Go).
                </p>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '16px', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: '12px', padding: '20px' }}>
              <span style={{ fontSize: '28px' }}>⚡</span>
              <div>
                <h3 style={{ fontSize: '15px', fontWeight: 700, color: '#fff', marginBottom: '6px' }}>Ephemereal & Stateless Storage</h3>
                <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', lineHeight: 1.5 }}>
                  Reports and findings are compiled on-the-fly directly from DB parameters, protecting asset reports from storage wipes or server updates.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── FEATURES SECTION ── */}
      <section id="features" style={{
        maxWidth: '1200px',
        margin: '0 auto',
        padding: '80px 40px',
      }}>
        <div style={{ textAlign: 'center', marginBottom: '50px' }}>
          <h2 style={{ fontSize: '32px', fontWeight: 800, letterSpacing: '-1px' }}>Core Automated Workflow</h2>
          <p style={{ fontSize: '14px', color: 'rgba(255,255,255,0.5)', marginTop: '8px' }}>
            Four integrated security steps running inside container pipelines.
          </p>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: '24px',
        }}>
          {/* Recon */}
          <div className="feature-card" style={{
            background: 'rgba(13, 13, 31, 0.25)',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            borderRadius: '16px',
            padding: '30px',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px',
          }}>
            <span style={{ fontSize: '28px' }}>🔍</span>
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>1. Asset Recon</h3>
            <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', lineHeight: 1.6 }}>
              Discovers assets, subdomains, and running ports using Subfinder, Amass, and unprivileged Nmap connect probes.
            </p>
          </div>

          {/* Scanning */}
          <div className="feature-card" style={{
            background: 'rgba(13, 13, 31, 0.25)',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            borderRadius: '16px',
            padding: '30px',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px',
          }}>
            <span style={{ fontSize: '28px' }}>🔬</span>
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>2. Vuln Scanning</h3>
            <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', lineHeight: 1.6 }}>
              Triggers Nuclei template engines, Nikto HTTP analyses, Dalfox XSS probes, and active OWASP ZAP scanning blocks.
            </p>
          </div>

          {/* Exploitation */}
          <div className="feature-card" style={{
            background: 'rgba(13, 13, 31, 0.25)',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            borderRadius: '16px',
            padding: '30px',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px',
          }}>
            <span style={{ fontSize: '28px' }}>💥</span>
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>3. Safe Exploit</h3>
            <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', lineHeight: 1.6 }}>
              Runs safe verification scripts against Web, Network, System Host, and Social Engineering indicators.
            </p>
          </div>

          {/* Reporting */}
          <div className="feature-card" style={{
            background: 'rgba(13, 13, 31, 0.25)',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            borderRadius: '16px',
            padding: '30px',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px',
          }}>
            <span style={{ fontSize: '28px' }}>📋</span>
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: '#fff' }}>4. vaultX Reports</h3>
            <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', lineHeight: 1.6 }}>
              Generates executive briefs, risk rating diagrams, and complete vulnerability details in HTML/PDF format.
            </p>
          </div>
        </div>
      </section>

      {/* ── SUBSCRIPTION SECTION ── */}
      <section id="pricing" style={{
        background: 'rgba(10, 10, 25, 0.5)',
        borderTop: '1px solid rgba(255, 255, 255, 0.03)',
        padding: '80px 40px 100px 40px',
      }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: '50px' }}>
            <h2 style={{ fontSize: '32px', fontWeight: 800, letterSpacing: '-1px' }}>Flexible Subscriptions</h2>
            <p style={{ fontSize: '14px', color: 'rgba(255,255,255,0.5)', marginTop: '8px' }}>
              Choose a VAPT tier tailored to your scanning scale.
            </p>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
            gap: '30px',
            maxWidth: '1000px',
            margin: '0 auto',
          }}>
            {/* Free Tier */}
            <div className="pricing-card" style={{
              background: 'rgba(13, 13, 31, 0.4)',
              border: '1px solid rgba(255, 255, 255, 0.05)',
              borderRadius: '16px',
              padding: '40px',
              display: 'flex',
              flexDirection: 'column',
              gap: '24px',
            }}>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff' }}>Community</h3>
                <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', marginTop: '4px' }}>For indie devs & hobbyists</p>
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px' }}>
                <span style={{ fontSize: '36px', fontWeight: 800, color: '#fff' }}>$0</span>
                <span style={{ fontSize: '12px', color: 'rgba(255,255,255,0.4)' }}>/ month</span>
              </div>
              <ul style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: 0, margin: 0, listStyle: 'none', fontSize: '13px', color: 'rgba(255,255,255,0.7)' }}>
                <li>✓ 1 Active scan target</li>
                <li>✓ Basic port scan (unprivileged)</li>
                <li>✓ Standard HTML report</li>
                <li>✗ AI-generated remediations</li>
                <li>✗ PDF download formatting</li>
              </ul>
              <button 
                onClick={() => scrollToSection('portal')}
                style={{
                  width: '100%',
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  padding: '12px',
                  color: '#fff',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  marginTop: 'auto',
                }}
              >
                Get Started
              </button>
            </div>

            {/* Pro Tier */}
            <div className="pricing-card" style={{
              background: 'rgba(13, 13, 31, 0.6)',
              border: '1px solid rgba(99, 102, 241, 0.4)',
              borderRadius: '16px',
              padding: '40px',
              display: 'flex',
              flexDirection: 'column',
              gap: '24px',
              position: 'relative',
            }}>
              <div style={{
                position: 'absolute',
                top: '-12px',
                right: '20px',
                background: 'linear-gradient(135deg, #a855f7 0%, #6366f1 100%)',
                color: '#fff',
                fontSize: '10px',
                fontWeight: 700,
                textTransform: 'uppercase',
                padding: '4px 12px',
                borderRadius: '100px',
                letterSpacing: '0.5px',
              }}>
                Recommended
              </div>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff' }}>Professional</h3>
                <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', marginTop: '4px' }}>For startups & tech teams</p>
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px' }}>
                <span style={{ fontSize: '36px', fontWeight: 800, color: '#fff' }}>$99</span>
                <span style={{ fontSize: '12px', color: 'rgba(255,255,255,0.4)' }}>/ month</span>
              </div>
              <ul style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: 0, margin: 0, listStyle: 'none', fontSize: '13px', color: 'rgba(255,255,255,0.7)' }}>
                <li>✓ Unlimited scan targets</li>
                <li>✓ Deep port scan (real Nmap engine)</li>
                <li>✓ Premium PDF/HTML VAPT reports</li>
                <li>✓ AI remediation secure code patches</li>
                <li>✓ Active exploitation stages</li>
              </ul>
              <button 
                onClick={() => scrollToSection('portal')}
                style={{
                  width: '100%',
                  background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
                  border: 'none',
                  borderRadius: '8px',
                  padding: '12px',
                  color: '#fff',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  boxShadow: '0 4px 15px rgba(99, 102, 241, 0.3)',
                  marginTop: 'auto',
                }}
              >
                Subscribe Now
              </button>
            </div>

            {/* Enterprise Tier */}
            <div className="pricing-card" style={{
              background: 'rgba(13, 13, 31, 0.4)',
              border: '1px solid rgba(255, 255, 255, 0.05)',
              borderRadius: '16px',
              padding: '40px',
              display: 'flex',
              flexDirection: 'column',
              gap: '24px',
            }}>
              <div>
                <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff' }}>Enterprise</h3>
                <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.5)', marginTop: '4px' }}>For large-scale infrastructure</p>
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px' }}>
                <span style={{ fontSize: '36px', fontWeight: 800, color: '#fff' }}>$499</span>
                <span style={{ fontSize: '12px', color: 'rgba(255,255,255,0.4)' }}>/ month</span>
              </div>
              <ul style={{ display: 'flex', flexDirection: 'column', gap: '12px', padding: 0, margin: 0, listStyle: 'none', fontSize: '13px', color: 'rgba(255,255,255,0.7)' }}>
                <li>✓ Custom exploitation stage playbooks</li>
                <li>✓ Dedicated private scan runners</li>
                <li>✓ REST API access & CI/CD pipeline hook</li>
                <li>✓ SAML SSO / Active Directory integration</li>
                <li>✓ 24/7 Security incident support</li>
              </ul>
              <button 
                onClick={() => scrollToSection('portal')}
                style={{
                  width: '100%',
                  background: 'rgba(255,255,255,0.03)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  padding: '12px',
                  color: '#fff',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  marginTop: 'auto',
                }}
              >
                Contact Sales
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ── FOOTER ── */}
      <footer style={{
        background: '#020208',
        borderTop: '1px solid rgba(255, 255, 255, 0.03)',
        padding: '40px 40px',
        textAlign: 'center',
        fontSize: '12px',
        color: 'rgba(255,255,255,0.4)',
      }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>© {new Date().getFullYear()} ArgoLock VAPT. All rights reserved.</div>
          <div style={{ display: 'flex', gap: '20px' }}>
            <span>Privacy Policy</span>
            <span>Terms of Service</span>
            <span>Security Statement</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
