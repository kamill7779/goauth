import type { PublicBrandConfig } from '../types/publicConfig';

const runtimeIconSelector = 'link[rel~="icon"][data-runtime-brand-icon="true"]';
const iconSelector = 'link[rel~="icon"]';

export function applyBrandHead(brand: PublicBrandConfig, doc: Document = document): void {
  const name = normalizeBrandName(brand);
  doc.title = name;

  const link = ensureIconLink(doc);
  link.referrerPolicy = 'no-referrer';

  const iconURL = brand.icon_url.trim();
  if (iconURL) {
    link.href = iconURL;
    link.removeAttribute('type');
    return;
  }

  link.type = 'image/svg+xml';
  link.href = brandIconDataURL(brand);
}

export function brandIconDataURL(brand: PublicBrandConfig): string {
  const name = normalizeBrandName(brand);
  const label = normalizeIconText(brand, name);
  const fontSize = Array.from(label).length > 1 ? 25 : 31;
  const svg = [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="${escapeXML(name)}">`,
    '<rect width="64" height="64" rx="16" fill="#111827"/>',
    '<rect x="3" y="3" width="58" height="58" rx="13" fill="none" stroke="#ffffff" stroke-opacity=".22" stroke-width="2"/>',
    `<text x="32" y="34" fill="#ffffff" font-family="Inter, Arial, sans-serif" font-size="${fontSize}" font-weight="700" text-anchor="middle" dominant-baseline="middle">${escapeXML(label)}</text>`,
    '</svg>',
  ].join('');

  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

function ensureIconLink(doc: Document): HTMLLinkElement {
  let link = doc.querySelector<HTMLLinkElement>(runtimeIconSelector) ?? doc.querySelector<HTMLLinkElement>(iconSelector);
  if (!link) {
    link = doc.createElement('link');
    link.rel = 'icon';
    doc.head.appendChild(link);
  }
  link.setAttribute('data-runtime-brand-icon', 'true');
  return link;
}

function normalizeBrandName(brand: PublicBrandConfig): string {
  return brand.name.trim() || 'GoAuth';
}

function normalizeIconText(brand: PublicBrandConfig, name: string): string {
  const text = brand.icon_text.trim() || name.trim().charAt(0) || 'G';
  return Array.from(text).slice(0, 2).join('').toUpperCase();
}

function escapeXML(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
