// Firebase Configuration for Loki Agency Vault
// Exclusively configured via environment variables (VITE_FIREBASE_* for Vite, FIREBASE_* for Node)
// Zero hardcoded API keys, app IDs, or messaging sender IDs.

const metaEnv = typeof import.meta !== 'undefined' ? (import.meta as any).env : undefined;
const env = metaEnv || (typeof process !== 'undefined' ? process.env : {}) || {};

export const firebaseConfig = {
  projectId: env.VITE_FIREBASE_PROJECT_ID || env.FIREBASE_PROJECT_ID || 'loki-agency-vault',
  appId: env.VITE_FIREBASE_APP_ID || '',
  storageBucket: env.VITE_FIREBASE_STORAGE_BUCKET || (env.VITE_FIREBASE_PROJECT_ID ? `${env.VITE_FIREBASE_PROJECT_ID}.firebasestorage.app` : ''),
  apiKey: env.VITE_FIREBASE_API_KEY || '',
  authDomain: env.VITE_FIREBASE_AUTH_DOMAIN || (env.VITE_FIREBASE_PROJECT_ID ? `${env.VITE_FIREBASE_PROJECT_ID}.firebaseapp.com` : ''),
  messagingSenderId: env.VITE_FIREBASE_MESSAGING_SENDER_ID || '',
};
