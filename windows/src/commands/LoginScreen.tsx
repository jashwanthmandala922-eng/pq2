import React, { useState } from 'react';
import { Box, Button, TextInput, Text, Spinner, Row, Column, Icon } from './components';
import { useAuth } from './commands/auth';
import { GlassCard, GlassButton, GlassOutlinedButton } from './theme/glass';

interface LoginScreenProps {
  onUnlock: (masterKey: Uint8Array) => void;
  totpEnabled?: boolean;
  passkeyAvailable?: boolean;
  biometricAvailable?: boolean;
}

type LoginStep = 'MASTER_PASSWORD' | 'TOTP' | 'AUTHENTICATED';

export function LoginScreen({ 
  onUnlock, 
  totpEnabled = false,
  passkeyAvailable = false, 
  biometricAvailable = false 
}: LoginScreenProps) {
  const {
    step,
    password,
    totpCode,
    error,
    loading,
    setPassword,
    setTotpCode,
    authenticateWithPassword,
    authenticateWithTotp,
    authenticateWithPasskey,
    authenticateWithBiometric,
  } = useAuth();

  const [isNewVault, setIsNewVault] = useState(false);

  const handlePasswordSubmit = async () => {
    const sessionKey = new Uint8Array(32);
    crypto.getRandomValues(sessionKey);
    
    await authenticateWithPassword((key) => {
      if (totpEnabled) {
        // Move to TOTP step (handled in component)
      } else {
        onUnlock(key);
      }
    });
  };

  const handleTotpSubmit = async () => {
    await authenticateWithTotp(onUnlock, new Uint8Array(32));
  };

  const handlePasskey = async () => {
    const success = await authenticateWithPasskey();
    if (success) {
      onUnlock(new Uint8Array(32));
    }
  };

  const handleBiometric = async () => {
    const success = await authenticateWithBiometric();
    if (success) {
      onUnlock(new Uint8Array(32));
    }
  };

  return (
    <Box
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%)',
        padding: '24px',
      }}
    >
      <Column style={{ width: '100%', maxWidth: '400px', gap: '24px' }}>
        {/* Logo */}
        <Box
          style={{
            width: '100px',
            height: '100px',
            borderRadius: '24px',
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            alignSelf: 'center',
            boxShadow: '0 8px 32px rgba(102, 126, 234, 0.4)',
          }}
        >
          <Text style={{ fontSize: '48px' }}>🔐</Text>
        </Box>

        {/* Title */}
        <Box style={{ textAlign: 'center' }}>
          <Text
            style={{
              fontSize: '32px',
              fontWeight: 'bold',
              background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
          >
            SecureVault
          </Text>
          <Text style={{ color: 'rgba(255,255,255,0.6)', marginTop: '8px' }}>
            {step === 'TOTP' 
              ? 'Enter TOTP Code' 
              : isNewVault 
                ? 'Create your vault' 
                : 'Post-quantum password manager'}
          </Text>
        </Box>

        {/* Login Card */}
        <GlassCard style={{ padding: '24px' }}>
          {step === 'MASTER_PASSWORD' && (
            <Column style={{ gap: '16px' }}>
              <Text style={{ fontSize: '18px', fontWeight: '600', color: '#fff' }}>
                {isNewVault ? 'Create Master Password' : 'Master Password'}
              </Text>

              <TextInput
                type="password"
                value={password}
                onChange={setPassword}
                placeholder="Enter master password"
                style={{
                  width: '100%',
                  padding: '14px',
                  borderRadius: '12px',
                  border: '1px solid rgba(255,255,255,0.2)',
                  background: 'rgba(255,255,255,0.1)',
                  color: '#fff',
                  fontSize: '16px',
                  outline: 'none',
                }}
              />

              {isNewVault && (
                <Box style={{ marginTop: '8px' }}>
                  <Box
                    style={{
                      height: '4px',
                      borderRadius: '2px',
                      background: 'rgba(255,255,255,0.1)',
                      overflow: 'hidden',
                    }}
                  >
                    <Box
                      style={{
                        width: `${Math.min(100, password.length * 5)}%`,
                        height: '100%',
                        background: password.length >= 12 ? '#4ade80' : '#fbbf24',
                        transition: 'width 0.3s',
                      }}
                    />
                  </Box>
                </Box>
              )}

              {error && (
                <Text style={{ color: '#f87171', fontSize: '14px' }}>{error}</Text>
              )}

              <Button
                onClick={isNewVault ? () => {} : handlePasswordSubmit}
                disabled={loading || !password}
                style={{
                  width: '100%',
                  padding: '14px',
                  borderRadius: '12px',
                  background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                  border: 'none',
                  color: '#fff',
                  fontSize: '16px',
                  fontWeight: '600',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  opacity: loading || !password ? 0.7 : 1,
                }}
              >
                {loading ? (
                  <Spinner size="20" />
                ) : (
                  isNewVault ? 'Create Vault' : totpEnabled ? 'Next' : 'Unlock'
                )}
              </Button>

              {!isNewVault && (
                <Button
                  onClick={() => setIsNewVault(true)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'rgba(255,255,255,0.6)',
                    cursor: 'pointer',
                    fontSize: '14px',
                  }}
                >
                  Create New Vault
                </Button>
              )}
            </Column>
          )}

          {step === 'TOTP' && (
            <Column style={{ gap: '16px' }}>
              <Row 
                onClick={() => {}}
                style={{ cursor: 'pointer', gap: '8px', alignItems: 'center' }}
              >
                <Text style={{ fontSize: '18px' }}>←</Text>
                <Text style={{ fontSize: '18px', fontWeight: '600', color: '#fff' }}>
                  Two-Factor Authentication
                </Text>
              </Row>

              <Text style={{ color: 'rgba(255,255,255,0.6)', fontSize: '14px' }}>
                Enter the 6-digit code from your authenticator app
              </Text>

              <TextInput
                type="text"
                value={totpCode}
                onChange={(v) => setTotpCode(v.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                style={{
                  width: '100%',
                  padding: '14px',
                  borderRadius: '12px',
                  border: '1px solid rgba(255,255,255,0.2)',
                  background: 'rgba(255,255,255,0.1)',
                  color: '#fff',
                  fontSize: '32px',
                  fontWeight: 'bold',
                  textAlign: 'center',
                  letterSpacing: '8px',
                  outline: 'none',
                }}
              />

              {error && (
                <Text style={{ color: '#f87171', fontSize: '14px' }}>{error}</Text>
              )}

              <Row style={{ gap: '12px' }}>
                <Button
                  onClick={() => {}}
                  style={{
                    flex: 1,
                    padding: '14px',
                    borderRadius: '12px',
                    background: 'rgba(255,255,255,0.1)',
                    border: '1px solid rgba(255,255,255,0.2)',
                    color: '#fff',
                    cursor: 'pointer',
                  }}
                >
                  Back
                </Button>
                <Button
                  onClick={handleTotpSubmit}
                  disabled={loading || totpCode.length !== 6}
                  style={{
                    flex: 1,
                    padding: '14px',
                    borderRadius: '12px',
                    background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                    border: 'none',
                    color: '#fff',
                    fontWeight: '600',
                    cursor: totpCode.length === 6 ? 'pointer' : 'not-allowed',
                    opacity: totpCode.length === 6 ? 1 : 0.7,
                  }}
                >
                  {loading ? <Spinner size="20" /> : 'Verify'}
                </Button>
              </Row>
            </Column>
          )}
        </GlassCard>

        {/* Alternative Auth Methods */}
        <Row style={{ gap: '12px' }}>
          {passkeyAvailable && (
            <GlassOutlinedButton onClick={handlePasskey} style={{ flex: 1 }}>
              <Text style={{ marginRight: '8px' }}>🔑</Text>
              Passkey
            </GlassOutlinedButton>
          )}
          
          {biometricAvailable && (
            <GlassOutlinedButton onClick={handleBiometric} style={{ flex: 1 }}>
              <Text style={{ marginRight: '8px' }}>👆</Text>
              Biometric
            </GlassOutlinedButton>
          )}
        </Row>

        {/* Footer */}
        <Box style={{ textAlign: 'center' }}>
          <Text style={{ color: 'rgba(255,255,255,0.4)', fontSize: '12px' }}>
            {totpEnabled ? 'ML-KEM • Argon2id • TOTP' : 'ML-KEM • Argon2id'}
          </Text>
          <Text style={{ color: 'rgba(255,255,255,0.4)', fontSize: '12px', marginTop: '4px' }}>
            Post-quantum secure
          </Text>
        </Box>
      </Column>
    </Box>
  );
}