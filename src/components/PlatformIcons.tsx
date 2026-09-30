import React from 'react';

export interface PlatformConfig {
  id: string;
  name: string;
  category: 'social' | 'ads' | 'cloud' | 'hosting' | 'database' | 'devtools' | 'ecommerce' | 'other';
  color: string;
}

export const PLATFORM_CATALOG: PlatformConfig[] = [
  { id: 'instagram', name: 'Instagram', category: 'social', color: '#E4405F' },
  { id: 'facebook', name: 'Facebook', category: 'social', color: '#1877F2' },
  { id: 'google-ads', name: 'Google Ads', category: 'ads', color: '#4285F4' },
  { id: 'google', name: 'Google Workspace', category: 'cloud', color: '#34A853' },
  { id: 'meta-business', name: 'Meta Business Suite', category: 'ads', color: '#0081FB' },
  { id: 'linkedin', name: 'LinkedIn', category: 'social', color: '#0A66C2' },
  { id: 'youtube', name: 'YouTube', category: 'social', color: '#FF0000' },
  { id: 'shopify', name: 'Shopify Admin', category: 'ecommerce', color: '#95BF47' },
  { id: 'cloudflare', name: 'Cloudflare', category: 'cloud', color: '#F38020' },
  { id: 'vercel', name: 'Vercel', category: 'hosting', color: '#E9E8DF' },
  { id: 'github', name: 'GitHub', category: 'devtools', color: '#E9E8DF' },
  { id: 'stripe', name: 'Stripe Gateway', category: 'ecommerce', color: '#635BFF' },
  { id: 'aws', name: 'Amazon Web Services', category: 'cloud', color: '#FF9900' },
  { id: 'production-db', name: 'Production Database', category: 'database', color: '#3FAF63' },
  { id: 'other', name: 'Other Custom Platform', category: 'other', color: '#C9A84E' },
];

export function PlatformIcon({ platformName, className = 'w-4 h-4' }: { platformName: string; className?: string }) {
  const norm = (platformName || '').toLowerCase().trim();

  if (norm.includes('instagram')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#E4405F" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect width="20" height="20" x="2" y="2" rx="5" ry="5" />
        <path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z" />
        <line x1="17.5" x2="17.51" y1="6.5" y2="6.5" />
      </svg>
    );
  }

  if (norm.includes('facebook')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#1877F2" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z" />
      </svg>
    );
  }

  if (norm.includes('google ads') || norm.includes('google-ads')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#4285F4" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6" />
      </svg>
    );
  }

  if (norm.includes('google')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#34A853" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
        <path d="M2 12h20" />
      </svg>
    );
  }

  if (norm.includes('meta')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#0081FB" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4 12c0-3.3 2.7-6 6-6 2.2 0 4.1 1.2 5.1 3 1-1.8 2.9-3 5.1-3 3.3 0 6 2.7 6 6s-2.7 6-6 6c-2.2 0-4.1-1.2-5.1-3-1 1.8-2.9 3-5.1 3-3.3 0-6-2.7-6-6z" />
      </svg>
    );
  }

  if (norm.includes('linkedin')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#0A66C2" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z" />
        <rect width="4" height="12" x="2" y="9" />
        <circle cx="4" cy="4" r="2" />
      </svg>
    );
  }

  if (norm.includes('youtube')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#FF0000" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M2.5 17a24.12 24.12 0 0 1 0-10 2 2 0 0 1 1.4-1.4 49.56 49.56 0 0 1 16.2 0A2 2 0 0 1 21.5 7a24.12 24.12 0 0 1 0 10 2 2 0 0 1-1.4 1.4 49.55 49.55 0 0 1-16.2 0A2 2 0 0 1 2.5 17" />
        <polygon points="10 15 15 12 10 9 10 15" />
      </svg>
    );
  }

  if (norm.includes('shopify')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#95BF47" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M6 2 3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4Z" />
        <path d="M3 6h18" />
        <path d="M16 10a4 4 0 0 1-8 0" />
      </svg>
    );
  }

  if (norm.includes('cloudflare')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#F38020" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" />
      </svg>
    );
  }

  if (norm.includes('vercel')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#E9E8DF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polygon points="12 2 22 20 2 20" />
      </svg>
    );
  }

  if (norm.includes('github')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#E9E8DF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
        <path d="M9 18c-4.51 2-5-2-7-2" />
      </svg>
    );
  }

  if (norm.includes('stripe')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#635BFF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect width="20" height="14" x="2" y="5" rx="2" />
        <line x1="2" x2="22" y1="10" y2="10" />
      </svg>
    );
  }

  if (norm.includes('aws')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#FF9900" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
      </svg>
    );
  }

  if (norm.includes('db') || norm.includes('database')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#3FAF63" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <ellipse cx="12" cy="5" rx="9" ry="3" />
        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
      </svg>
    );
  }

  // Default fallback
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#C9A84E" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="12" x2="12" y1="8" y2="12" />
      <line x1="12" x2="12.01" y1="16" y2="16" />
    </svg>
  );
}
