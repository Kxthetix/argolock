import React, { useState, useEffect, useRef } from 'react';

interface OTPModalProps {
  email: string;
  isOpen: boolean;
  onClose: () => void;
  onVerifySuccess: (token: string, email: string) => void;
  onResendOtp: () => Promise<void>;
}

export function OTPModal({ email, isOpen, onClose, onVerifySuccess, onResendOtp }: OTPModalProps) {
  const [code, setCode] = useState<string[]>(Array(6).fill(''));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [timer, setTimer] = useState(60);
  const [resending, setResending] = useState(false);
  const inputsRef = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    if (isOpen) {
      setCode(Array(6).fill(''));
      setError('');
      setTimer(60);
      setTimeout(() => {
        inputsRef.current[0]?.focus();
      }, 100);
    }
  }, [isOpen]);

  useEffect(() => {
    if (timer > 0 && isOpen) {
      const interval = setInterval(() => setTimer((t) => t - 1), 1000);
      return () => clearInterval(interval);
    }
  }, [timer, isOpen]);

  if (!isOpen) return null;

  const handleChange = (index: number, value: string) => {
    if (isNaN(Number(value))) return; // only allow numbers
    const newCode = [...code];
    newCode[index] = value.substring(value.length - 1);
    setCode(newCode);

    // Auto-focus next input
    if (value && index < 5) {
      inputsRef.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !code[index] && index > 0) {
      inputsRef.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pasteData = e.clipboardData.getData('text').trim();
    if (pasteData.length === 6 && !isNaN(Number(pasteData))) {
      setCode(pasteData.split(''));
      inputsRef.current[5]?.focus();
    }
  };

  const handleVerify = async () => {
    const fullCode = code.join('');
    if (fullCode.length !== 6) {
      setError('Please enter all 6 digits');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const { authApi } = await import('../lib/api');
      const response = await authApi.verifyOtp(email, fullCode);
      onVerifySuccess(response.access_token, response.email);
    } catch (err: any) {
      setError(err.message || 'Verification failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (timer > 0) return;
    setResending(true);
    setError('');
    try {
      await onResendOtp();
      setTimer(60);
    } catch (err: any) {
      setError(err.message || 'Failed to resend OTP.');
    } finally {
      setResending(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(4, 4, 13, 0.8)',
      backdropFilter: 'blur(8px)',
      WebkitBackdropFilter: 'blur(8px)',
      zIndex: 1000,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '20px',
    }}>
      <div style={{
        background: 'rgba(13, 13, 35, 0.65)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '16px',
        padding: '32px',
        maxWidth: '420px',
        width: '100%',
        boxShadow: '0 20px 40px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        textAlign: 'center',
        position: 'relative',
      }}>
        {/* Close Button */}
        <button 
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '20px',
            right: '20px',
            background: 'none',
            border: 'none',
            color: 'rgba(255, 255, 255, 0.4)',
            cursor: 'pointer',
            fontSize: '18px',
          }}
        >
          ✕
        </button>

        <h3 style={{ fontSize: '20px', fontWeight: 700, marginBottom: '8px', color: '#fff' }}>
          Verify Your Email
        </h3>
        <p style={{ fontSize: '13px', color: 'rgba(255, 255, 255, 0.6)', marginBottom: '24px', lineHeight: '1.5' }}>
          We sent a verification code to <strong style={{ color: '#fff' }}>{email}</strong>. Enter the 6-digit code below.
        </p>

        {/* Inputs */}
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'center', marginBottom: '24px' }}>
          {code.map((digit, i) => (
            <input
              key={i}
              type="text"
              maxLength={1}
              value={digit}
              ref={(el) => { inputsRef.current[i] = el; }}
              onChange={(e) => handleChange(i, e.target.value)}
              onKeyDown={(e) => handleKeyDown(i, e)}
              onPaste={i === 0 ? handlePaste : undefined}
              style={{
                width: '45px',
                height: '50px',
                borderRadius: '8px',
                background: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                textAlign: 'center',
                fontSize: '20px',
                fontWeight: 600,
                color: '#fff',
                outline: 'none',
                transition: 'border-color 0.2s, box-shadow 0.2s',
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = '#6366f1';
                e.currentTarget.style.boxShadow = '0 0 10px rgba(99, 102, 241, 0.3)';
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.1)';
                e.currentTarget.style.boxShadow = 'none';
              }}
            />
          ))}
        </div>

        {error && (
          <p style={{ color: '#ef4444', fontSize: '13px', marginBottom: '16px' }}>{error}</p>
        )}

        <button
          onClick={handleVerify}
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
            cursor: 'pointer',
            marginBottom: '20px',
            transition: 'opacity 0.2s',
            opacity: loading ? 0.7 : 1,
          }}
        >
          {loading ? 'Verifying...' : 'Verify Code'}
        </button>

        <p style={{ fontSize: '12px', color: 'rgba(255, 255, 255, 0.4)' }}>
          Didn't receive the code?{' '}
          <button
            onClick={handleResend}
            disabled={timer > 0 || resending}
            style={{
              background: 'none',
              border: 'none',
              color: timer > 0 ? 'rgba(255, 255, 255, 0.3)' : '#6366f1',
              cursor: timer > 0 ? 'default' : 'pointer',
              fontWeight: 600,
              padding: 0,
            }}
          >
            {resending ? 'Resending...' : timer > 0 ? `Resend in ${timer}s` : 'Resend Code'}
          </button>
        </p>
      </div>
    </div>
  );
}
