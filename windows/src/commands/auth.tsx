import { useState, useCallback } from 'react';

interface WebAuthnCredential {
  id: string;
  rawId: string;
  type: 'public-key';
}

interface AuthenticatorAttestationResponse {
  clientDataJSON: string;
  attestationObject: string;
}

interface AuthenticatorAssertionResponse {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string;
}

type LoginStep = 'PASSWORD' | 'TOTP' | 'AUTHENTICATED';

interface LoginConfig {
  totpEnabled: boolean;
  passkeyEnabled: boolean;
  biometricEnabled: boolean;
}

export function useAuth() {
  const [step, setStep] = useState<LoginStep>('PASSWORD');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const authenticateWithPassword = useCallback(async (onSuccess: (key: Uint8Array) => void) => {
    setLoading(true);
    setError(null);
    try {
      const salt = new TextEncoder().encode('SecureVault-Salt-v1');
      const key = await deriveKeyArgon2(password, salt);
      
      if (true) {
        setStep('TOTP');
      } else {
        onSuccess(new Uint8Array(key));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Authentication failed');
    } finally {
      setLoading(false);
    }
  }, [password]);

  const authenticateWithTotp = useCallback(async (
    onSuccess: (key: Uint8Array, sessionKey: Uint8Array) => void,
    sessionKey: Uint8Array
  ) => {
    setLoading(true);
    setError(null);
    try {
      const valid = verifyTotpCode(totpCode, sessionKey);
      if (!valid) {
        setError('Invalid TOTP code');
        return;
      }
      setStep('AUTHENTICATED');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'TOTP verification failed');
    } finally {
      setLoading(false);
    }
  }, [totpCode]);

  const generatePasskey = useCallback(async (): Promise<PublicKeyCredential | null> => {
    setLoading(true);
    setError(null);
    try {
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      const options: PublicKeyCredentialCreationOptions = {
        challenge,
        rp: {
          name: 'SecureVault',
          id: window.location.hostname || 'securevault.local',
        },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: 'SecureVault User',
          displayName: 'SecureVault User',
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },
          { alg: -257, type: 'public-key' },
        ],
        timeout: 60000,
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'preferred',
        },
        attestation: 'none',
      };

      const credential = await navigator.credentials.create({
        publicKey: options,
      }) as PublicKeyCredential | null;

      return credential;
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Passkey registration failed');
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const authenticateWithPasskey = useCallback(async (): Promise<boolean> => {
    setLoading(true);
    setError(null);
    try {
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      const options: PublicKeyCredentialRequestOptions = {
        challenge,
        rpId: window.location.hostname || 'securevault.local',
        timeout: 60000,
        userVerification: 'preferred',
      };

      const credential = await navigator.credentials.get({
        publicKey: options,
      }) as PublicKeyCredential | null;

      if (!credential) {
        setError('No credential selected');
        return false;
      }

      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Passkey authentication failed');
      return false;
    } finally {
      setLoading(false);
    }
  }, []);

  const authenticateWithBiometric = useCallback(async (): Promise<boolean> => {
    return authenticateWithPasskey();
  }, [authenticateWithPasskey]);

  const generateTotpSecret = useCallback((): { secret: Uint8Array; uri: string } => {
    const secret = new Uint8Array(20);
    crypto.getRandomValues(secret);
    
    const base32Secret = base32Encode(secret);
    const uri = `otpauth://totp/SecureVault:user?secret=${base32Secret}&issuer=SecureVault&algorithm=SHA256&digits=6&period=30`;
    
    return { secret, uri };
  }, []);

  const generateTotpCode = useCallback((secret: Uint8Array): string => {
    const counter = Math.floor(Date.now() / 30000);
    return generateHotp(secret, counter);
  }, []);

  const verifyTotpCode = useCallback((code: string, secret: Uint8Array): boolean => {
    const currentCounter = Math.floor(Date.now() / 30000);
    for (let offset = -1; offset <= 1; offset++) {
      const expectedCode = generateHotp(secret, currentCounter + offset);
      if (constantTimeEquals(code, expectedCode)) {
        return true;
      }
    }
    return false;
  }, []);

  const lock = useCallback(() => {
    setStep('PASSWORD');
    setPassword('');
    setTotpCode('');
    setError(null);
  }, []);

  return {
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
    generatePasskey,
    generateTotpSecret,
    generateTotpCode,
    verifyTotpCode,
    lock,
  };
}

async function deriveKeyArgon2(password: string, salt: Uint8Array): Promise<ArrayBuffer> {
  const passwordBytes = new TextEncoder().encode(password);
  const input = new Uint8Array(passwordBytes.length + salt.length);
  input.set(passwordBytes, 0);
  input.set(salt, passwordBytes.length);
  
  const hashBuffer = await crypto.subtle.digest('SHA-256', input);
  return hashBuffer;
}

function generateHotp(secret: Uint8Array, counter: number): string {
  const counterBytes = new ArrayBuffer(8);
  const view = new DataView(counterBytes);
  view.setBigUint64(0, BigInt(counter), false);
  
  const key = crypto.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const hash = crypto.subtle.sign('HMAC', await key, counterBytes);
  const hashArray = new Uint8Array(hash);
  
  const offset = hashArray[hashArray.length - 1] & 0x0f;
  const binary = 
    ((hashArray[offset] & 0x7f) << 24) |
    ((hashArray[offset + 1] & 0xff) << 16) |
    ((hashArray[offset + 2] & 0xff) << 8) |
    (hashArray[offset + 3] & 0xff);
  
  const otp = binary % 1000000;
  return otp.toString().padStart(6, '0');
}

function base32Encode(data: Uint8Array): string {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result = '';
  let buffer = 0;
  let bitsLeft = 0;
  
  for (const byte of data) {
    buffer = (buffer << 8) | byte;
    bitsLeft += 8;
    
    while (bitsLeft >= 5) {
      bitsLeft -= 5;
      result += ALPHABET[(buffer >> bitsLeft) & 0x1f];
    }
  }
  
  if (bitsLeft > 0) {
    result += ALPHABET[(buffer << (5 - bitsLeft)) & 0x1f];
  }
  
  return result;
}

function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

export type { LoginStep, LoginConfig };