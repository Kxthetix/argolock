import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { IS_DEMO, API_BASE } from '../lib/api';

export function Login() {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [step, setStep] = useState(1); // 1 = Email, 2 = OTP
  const [demoOtp, setDemoOtp] = useState('');
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

  const handleSendOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;

    setLoading(true);
    setError('');
    setSuccessMsg('');

    if (IS_DEMO) {
      // Simulate sending OTP locally in frontend for standalone static builds
      setTimeout(() => {
        const randomOtp = Math.floor(100000 + Math.random() * 900000).toString();
        setDemoOtp(randomOtp);
        setStep(2);
        setSuccessMsg('Demo Mode: Verification code generated!');
        setLoading(false);
      }, 600);
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/auth/send-otp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });

      let data: any = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        throw new Error(`Server error (${response.status}): Invalid response format`);
      }

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to send verification code');
      }

      setDemoOtp(data.otp || '');
      setStep(2);
      setSuccessMsg('Verification code sent! Please check the logs.');
    } catch (err: any) {
      setError(err.message || 'An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!otp) return;

    setLoading(true);
    setError('');

    if (IS_DEMO) {
      // Simulate verifying OTP locally in frontend for standalone static builds
      setTimeout(() => {
        if (otp === demoOtp || otp === '123456') {
          localStorage.setItem('auth_token', 'mock-demo-jwt-token');
          localStorage.setItem('auth_email', email);
          window.location.href = '/';
        } else {
          setError(`Invalid verification code. (Hint: enter ${demoOtp})`);
          setLoading(false);
        }
      }, 500);
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/auth/verify-otp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, otp }),
      });

      let data: any = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        throw new Error(`Server error (${response.status}): Invalid response format`);
      }

      if (!response.ok) {
        throw new Error(data.detail || 'Invalid verification code');
      }

      // Save credentials in local storage
      localStorage.setItem('auth_token', data.access_token);
      localStorage.setItem('auth_email', data.email);

      // Force page reload to trigger root router state check or navigate directly
      window.location.href = '/';
    } catch (err: any) {
      setError(err.message || 'An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: '#050510',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 9999,
      fontFamily: "'Inter', sans-serif",
      overflow: 'hidden',
    }}>
      {/* ── Background Glowing Orbs ── */}
      <div style={{
        position: 'absolute',
        width: '500px',
        height: '500px',
        background: 'radial-gradient(circle, rgba(99,102,241,0.15) 0%, rgba(99,102,241,0) 70%)',
        top: '-10%',
        left: '-10%',
        borderRadius: '50%',
        filter: 'blur(40px)',
        pointerEvents: 'none',
      }} />
      <div style={{
        position: 'absolute',
        width: '600px',
        height: '600px',
        background: 'radial-gradient(circle, rgba(168,85,247,0.1) 0%, rgba(168,85,247,0) 70%)',
        bottom: '-15%',
        right: '-10%',
        borderRadius: '50%',
        filter: 'blur(50px)',
        pointerEvents: 'none',
      }} />

      {/* ── Glassmorphism Login Container ── */}
      <div style={{
        width: '420px',
        background: 'rgba(13, 13, 31, 0.4)',
        border: '1px solid rgba(99, 102, 241, 0.2)',
        borderRadius: '16px',
        padding: '40px',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.5), 0 0 30px rgba(99, 102, 241, 0.1)',
        position: 'relative',
        zIndex: 10,
        display: 'flex',
        flexDirection: 'column',
        gap: '24px',
      }}>
        {/* ── Brand Header ── */}
        <div style={{ textAlign: 'center' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '56px',
            height: '56px',
            borderRadius: '12px',
            background: 'rgba(99, 102, 241, 0.1)',
            border: '1px solid rgba(99, 102, 241, 0.3)',
            marginBottom: '16px',
            boxShadow: '0 0 15px rgba(99, 102, 241, 0.2)',
            color: '#6366f1',
            fontSize: '24px',
          }}>
            🛡️
          </div>
          <h2 style={{
            fontSize: '22px',
            fontWeight: 800,
            letterSpacing: '-0.5px',
            background: 'linear-gradient(135deg, #fff 0%, rgba(255,255,255,0.7) 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            marginBottom: '6px',
          }}>
            ArgoLock Security
          </h2>
          <p style={{
            fontSize: '13px',
            color: 'rgba(255,255,255,0.5)',
          }}>
            AI-Powered VAPT Platform Authentication
          </p>
        </div>

        {/* ── Forms ── */}
        {step === 1 ? (
          <form onSubmit={handleSendOtp} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <label style={{
                fontSize: '12px',
                fontWeight: 600,
                color: 'rgba(255,255,255,0.7)',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
              }}>
                Email Address
              </label>
              <input
                type="email"
                required
                placeholder="name@domain.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={{
                  width: '100%',
                  background: 'rgba(5, 5, 16, 0.6)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '8px',
                  padding: '12px 16px',
                  color: '#fff',
                  fontSize: '14px',
                  outline: 'none',
                  transition: 'border-color 0.2s, box-shadow 0.2s',
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = '#6366f1';
                  e.target.style.boxShadow = '0 0 10px rgba(99,102,241,0.2)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(255, 255, 255, 0.1)';
                  e.target.style.boxShadow = 'none';
                }}
              />
            </div>

            {error && (
              <div style={{
                background: 'rgba(255, 59, 48, 0.1)',
                border: '1px solid rgba(255, 59, 48, 0.2)',
                borderRadius: '8px',
                padding: '10px 14px',
                color: '#ff453a',
                fontSize: '12px',
              }}>
                ⚠️ {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              style={{
                width: '100%',
                background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
                border: 'none',
                borderRadius: '8px',
                padding: '12px',
                color: '#fff',
                fontSize: '14px',
                fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
                transition: 'opacity 0.2s, transform 0.1s',
                boxShadow: '0 4px 15px rgba(99, 102, 241, 0.3)',
              }}
              onMouseOver={(e) => { e.currentTarget.style.opacity = '0.9'; }}
              onMouseOut={(e) => { e.currentTarget.style.opacity = '1'; }}
              onMouseDown={(e) => { e.currentTarget.style.transform = 'scale(0.98)'; }}
              onMouseUp={(e) => { e.currentTarget.style.transform = 'scale(1)'; }}
            >
              {loading ? 'Sending code...' : 'Send Verification Code'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleVerifyOtp} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <label style={{
                  fontSize: '12px',
                  fontWeight: 600,
                  color: 'rgba(255,255,255,0.7)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                }}>
                  Verification Code
                </label>
                <button
                  type="button"
                  onClick={() => setStep(1)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#818cf8',
                    fontSize: '12px',
                    cursor: 'pointer',
                    fontWeight: 500,
                  }}
                >
                  Change Email
                </button>
              </div>
              <input
                type="text"
                required
                maxLength={6}
                placeholder="6-digit code"
                value={otp}
                onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
                style={{
                  width: '100%',
                  background: 'rgba(5, 5, 16, 0.6)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: '8px',
                  padding: '12px 16px',
                  color: '#fff',
                  fontSize: '16px',
                  fontWeight: 600,
                  letterSpacing: '4px',
                  textAlign: 'center',
                  outline: 'none',
                  transition: 'border-color 0.2s, box-shadow 0.2s',
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = '#6366f1';
                  e.target.style.boxShadow = '0 0 10px rgba(99,102,241,0.2)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(255, 255, 255, 0.1)';
                  e.target.style.boxShadow = 'none';
                }}
              />
            </div>

            {successMsg && (
              <div style={{
                background: 'rgba(16, 185, 129, 0.1)',
                border: '1px solid rgba(16, 185, 129, 0.2)',
                borderRadius: '8px',
                padding: '10px 14px',
                color: '#34c759',
                fontSize: '12px',
              }}>
                {successMsg}
              </div>
            )}

            {error && (
              <div style={{
                background: 'rgba(255, 59, 48, 0.1)',
                border: '1px solid rgba(255, 59, 48, 0.2)',
                borderRadius: '8px',
                padding: '10px 14px',
                color: '#ff453a',
                fontSize: '12px',
              }}>
                ⚠️ {error}
              </div>
            )}

            {/* ── Demo Mode OTP Display ── */}
            {demoOtp && (
              <div style={{
                background: 'rgba(99, 102, 241, 0.1)',
                border: '1px dashed rgba(99, 102, 241, 0.3)',
                borderRadius: '8px',
                padding: '12px',
                textAlign: 'center',
                fontSize: '12px',
                color: '#818cf8',
              }}>
                💡 <strong>Demo Mode:</strong> Enter verification code:{' '}
                <strong style={{ fontSize: '14px', color: '#fff', background: 'rgba(255,255,255,0.1)', padding: '2px 6px', borderRadius: '4px', marginLeft: '4px' }}>
                  {demoOtp}
                </strong>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              style={{
                width: '100%',
                background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
                border: 'none',
                borderRadius: '8px',
                padding: '12px',
                color: '#fff',
                fontSize: '14px',
                fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
                transition: 'opacity 0.2s, transform 0.1s',
                boxShadow: '0 4px 15px rgba(99, 102, 241, 0.3)',
              }}
              onMouseOver={(e) => { e.currentTarget.style.opacity = '0.9'; }}
              onMouseOut={(e) => { e.currentTarget.style.opacity = '1'; }}
              onMouseDown={(e) => { e.currentTarget.style.transform = 'scale(0.98)'; }}
              onMouseUp={(e) => { e.currentTarget.style.transform = 'scale(1)'; }}
            >
              {loading ? 'Verifying...' : 'Verify & Log In'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
