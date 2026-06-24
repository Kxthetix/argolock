import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

export function OAuthCallback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState('');

  useEffect(() => {
    const token = searchParams.get('token');
    const email = searchParams.get('email');
    const err = searchParams.get('error');

    if (err) {
      setError(err);
      setTimeout(() => navigate('/login'), 3000);
      return;
    }

    if (token && email) {
      localStorage.setItem('auth_token', token);
      localStorage.setItem('auth_email', email);
      window.location.href = '/';
    } else {
      setError('Invalid callback parameters. Redirecting...');
      setTimeout(() => navigate('/login'), 2000);
    }
  }, [searchParams, navigate]);

  return (
    <div style={{
      background: '#04040d',
      color: '#fff',
      fontFamily: "'Inter', sans-serif",
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      flexDirection: 'column',
      gap: '20px',
    }}>
      {error ? (
        <>
          <div style={{
            width: '48px',
            height: '48px',
            borderRadius: '50%',
            background: 'rgba(255, 59, 48, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '24px',
          }}>
            ✕
          </div>
          <p style={{ color: '#ff453a', fontSize: '14px' }}>{error}</p>
          <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '12px' }}>Redirecting to login...</p>
        </>
      ) : (
        <>
          <div style={{
            width: '48px',
            height: '48px',
            border: '3px solid rgba(99, 102, 241, 0.3)',
            borderTopColor: '#6366f1',
            borderRadius: '50%',
            animation: 'spin 0.8s linear infinite',
          }} />
          <p style={{ color: 'rgba(255,255,255,0.7)', fontSize: '14px' }}>
            Completing sign-in...
          </p>
          <style>{`
            @keyframes spin {
              to { transform: rotate(360deg); }
            }
          `}</style>
        </>
      )}
    </div>
  );
}
