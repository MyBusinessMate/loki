import React, { useState } from 'react';

export interface PlatformConfig {
  id: string;
  name: string;
  category: 'social' | 'ads' | 'cloud' | 'hosting' | 'database' | 'devtools' | 'ecommerce' | 'marketing' | 'other';
  color: string;
  iconPath?: string;
}

export const PLATFORM_CATALOG: PlatformConfig[] = [
  { id: 'instagram', name: 'Instagram', category: 'social', color: '#E4405F', iconPath: '/svgs/instagram.svg' },
  { id: 'facebook', name: 'Facebook', category: 'social', color: '#1877F2', iconPath: '/svgs/facebook.svg' },
  { id: 'meta-business', name: 'Meta Business Suite', category: 'ads', color: '#0081FB', iconPath: '/svgs/meta.svg' },
  { id: 'google-ads', name: 'Google Ads', category: 'ads', color: '#4285F4', iconPath: '/svgs/google-ads.svg' },
  { id: 'google-analytics', name: 'Google Analytics', category: 'ads', color: '#E37400', iconPath: '/svgs/google-analytics.svg' },
  { id: 'google-workspace', name: 'Google Workspace', category: 'cloud', color: '#4285F4', iconPath: '/svgs/google.svg' },
  { id: 'google-drive', name: 'Google Drive', category: 'cloud', color: '#1FA463', iconPath: '/svgs/google-drive-2026.svg' },
  { id: 'gmail', name: 'Gmail', category: 'cloud', color: '#EA4335', iconPath: '/svgs/gmail-2026.svg' },
  { id: 'linkedin', name: 'LinkedIn', category: 'social', color: '#0A66C2', iconPath: '/svgs/linkedin.svg' },
  { id: 'youtube', name: 'YouTube', category: 'social', color: '#FF0000', iconPath: '/svgs/youtube.svg' },
  { id: 'x-twitter', name: 'X (Formerly Twitter)', category: 'social', color: '#FFFFFF', iconPath: '/svgs/x-formerly-twitter.svg' },
  { id: 'reddit', name: 'Reddit', category: 'social', color: '#FF4500', iconPath: '/svgs/reddit.svg' },
  { id: 'openai', name: 'OpenAI / ChatGPT', category: 'devtools', color: '#10A37F', iconPath: '/svgs/openai.svg' },
  { id: 'claude', name: 'Claude (Anthropic)', category: 'devtools', color: '#D97757', iconPath: '/svgs/claude.svg' },
  { id: 'hugging-face', name: 'Hugging Face', category: 'devtools', color: '#FFD21E', iconPath: '/svgs/hugging-face.svg' },
  { id: 'github', name: 'GitHub', category: 'devtools', color: '#FFFFFF', iconPath: '/svgs/github.svg' },
  { id: 'vercel', name: 'Vercel', category: 'hosting', color: '#FFFFFF', iconPath: '/svgs/vercel.svg' },
  { id: 'n8n', name: 'n8n Automation', category: 'devtools', color: '#EA4B71', iconPath: '/svgs/n8n.svg' },
  { id: 'airtable', name: 'Airtable', category: 'database', color: '#18BFFF', iconPath: '/svgs/airtable.svg' },
  { id: 'firebase', name: 'Firebase Console', category: 'database', color: '#FFCA28', iconPath: '/svgs/firebase-studio.svg' },
  { id: 'apollo-io', name: 'Apollo.io', category: 'marketing', color: '#FECF40', iconPath: '/svgs/apollodotio.svg' },
  { id: 'brevo', name: 'Brevo', category: 'marketing', color: '#0B996F', iconPath: '/svgs/brevo.svg' },
  { id: 'mailchimp', name: 'Mailchimp', category: 'marketing', color: '#FFE01B', iconPath: '/svgs/mailchimp.svg' },
  { id: 'resend', name: 'Resend', category: 'devtools', color: '#FDFDFD', iconPath: '/svgs/resend.svg' },
  { id: 'substack', name: 'Substack', category: 'social', color: '#FF6719', iconPath: '/svgs/substack.svg' },
  { id: 'medium', name: 'Medium', category: 'social', color: '#FFFFFF', iconPath: '/svgs/medium.svg' },
  { id: 'shopify', name: 'Shopify Admin', category: 'ecommerce', color: '#95BF47' },
  { id: 'stripe', name: 'Stripe Gateway', category: 'ecommerce', color: '#635BFF' },
  { id: 'cloudflare', name: 'Cloudflare', category: 'cloud', color: '#F38020' },
  { id: 'aws', name: 'Amazon Web Services', category: 'cloud', color: '#FF9900' },
  { id: 'production-db', name: 'Production Database', category: 'database', color: '#3FAF63' },
  { id: 'other', name: 'Other Custom Platform', category: 'other', color: '#C9A84E' },
];

export function getPlatformSvgPath(platformName: string): string | null {
  const norm = (platformName || '').toLowerCase().trim();
  if (!norm) return null;

  if (norm.includes('instagram') || norm === 'ig') return '/svgs/instagram.svg';
  if (norm.includes('facebook') || norm === 'fb') return '/svgs/facebook.svg';
  if (norm.includes('google ads') || norm.includes('google-ads') || norm.includes('adwords')) return '/svgs/google-ads.svg';
  if (norm.includes('google analytics') || norm.includes('google-analytics') || norm.includes('ga4')) return '/svgs/google-analytics.svg';
  if (norm.includes('google drive') || norm.includes('google-drive') || norm.includes('gdrive')) return '/svgs/google-drive-2026.svg';
  if (norm.includes('gmail') || norm.includes('google mail')) return '/svgs/gmail-2026.svg';
  if (norm.includes('google workspace') || norm.includes('google') || norm.includes('workspace')) return '/svgs/google.svg';
  if (norm.includes('meta business') || norm.includes('meta') || norm.includes('business suite')) return '/svgs/meta.svg';
  if (norm.includes('linkedin')) return '/svgs/linkedin.svg';
  if (norm.includes('youtube') || norm === 'yt') return '/svgs/youtube.svg';
  if (norm.includes('x (formerly twitter)') || norm.includes('twitter') || norm.includes('x-formerly-twitter') || norm === 'x') return '/svgs/x-formerly-twitter.svg';
  if (norm.includes('reddit')) return '/svgs/reddit.svg';
  if (norm.includes('openai') || norm.includes('chatgpt') || norm.includes('gpt')) return '/svgs/openai.svg';
  if (norm.includes('claude') || norm.includes('anthropic')) return '/svgs/claude.svg';
  if (norm.includes('hugging face') || norm.includes('hugging-face') || norm.includes('huggingface') || norm === 'hf') return '/svgs/hugging-face.svg';
  if (norm.includes('github')) return '/svgs/github.svg';
  if (norm.includes('vercel')) return '/svgs/vercel.svg';
  if (norm.includes('n8n')) return '/svgs/n8n.svg';
  if (norm.includes('airtable')) return '/svgs/airtable.svg';
  if (norm.includes('firebase')) return '/svgs/firebase-studio.svg';
  if (norm.includes('apollo') || norm.includes('apollodotio')) return '/svgs/apollodotio.svg';
  if (norm.includes('brevo') || norm.includes('sendinblue')) return '/svgs/brevo.svg';
  if (norm.includes('mailchimp')) return '/svgs/mailchimp.svg';
  if (norm.includes('resend')) return '/svgs/resend.svg';
  if (norm.includes('substack')) return '/svgs/substack.svg';
  if (norm.includes('medium')) return '/svgs/medium.svg';

  return null;
}

export function PlatformIcon({ platformName, className = 'w-4 h-4' }: { platformName: string; className?: string }) {
  const [loadFailed, setLoadFailed] = useState(false);
  const norm = (platformName || '').toLowerCase().trim();
  const svgPath = getPlatformSvgPath(platformName);

  // Render official vector SVG from public catalog when available
  if (svgPath && !loadFailed) {
    return (
      <img
        src={svgPath}
        alt={platformName || 'Platform'}
        className={`${className} object-contain inline-block shrink-0`}
        onError={() => setLoadFailed(true)}
        loading="lazy"
      />
    );
  }

  // Graceful fallback vectors for non-SVG platforms or offline/error recovery
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

  if (norm.includes('stripe')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#635BFF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect width="20" height="14" x="2" y="5" rx="2" />
        <line x1="2" x2="22" y1="10" y2="10" />
      </svg>
    );
  }

  if (norm.includes('aws') || norm.includes('amazon')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#FF9900" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
      </svg>
    );
  }

  if (norm.includes('db') || norm.includes('database') || norm.includes('sql') || norm.includes('postgres') || norm.includes('mongo')) {
    return (
      <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#3FAF63" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <ellipse cx="12" cy="5" rx="9" ry="3" />
        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
      </svg>
    );
  }

  // Default fallback icon with golden shield/key theme
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="#C9A84E" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="12" x2="12" y1="8" y2="12" />
      <line x1="12" x2="12.01" y1="16" y2="16" />
    </svg>
  );
}
