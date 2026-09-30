// Firebase Configuration for Loki Agency Vault
// Dedicated Isolated Project: loki-agency-vault
// Supports both direct cloud/MCP and standard environment variable fallback (VITE_FIREBASE_*)

const metaEnv = typeof import.meta !== 'undefined' ? (import.meta as any).env : undefined;
const env = metaEnv || (typeof process !== 'undefined' ? process.env : {}) || {};

export const firebaseConfig = {
  projectId: env.VITE_FIREBASE_PROJECT_ID || env.FIREBASE_PROJECT_ID || "loki-agency-vault",
  appId: env.VITE_FIREBASE_APP_ID || "1:362141834407:web:fcccca568b840ac0a68f82",
  storageBucket: env.VITE_FIREBASE_STORAGE_BUCKET || "loki-agency-vault.firebasestorage.app",
  apiKey: env.VITE_FIREBASE_API_KEY || "AIzaSyBAjlZjAx_W41O7t-putJk5X_0od-wfXww",
  authDomain: env.VITE_FIREBASE_AUTH_DOMAIN || "loki-agency-vault.firebaseapp.com",
  messagingSenderId: env.VITE_FIREBASE_MESSAGING_SENDER_ID || "362141834407",
};
