import { useEffect, useState } from 'react';
import type { CSSProperties } from 'react';
import type { PublicBrandConfig } from '../types/publicConfig';

type BrandMarkProps = {
  brand: PublicBrandConfig;
  size?: 'sm' | 'md' | 'lg';
  orientation?: 'horizontal' | 'stacked';
  showTagline?: boolean;
  align?: 'left' | 'center';
};

const sizeConfig = {
  sm: { icon: 32, radius: 8, name: 14, tagline: 10, gap: 10 },
  md: { icon: 44, radius: 11, name: 18, tagline: 12, gap: 12 },
  lg: { icon: 56, radius: 14, name: 22, tagline: 13, gap: 14 },
};

export default function BrandMark({
  brand,
  size = 'sm',
  orientation = 'horizontal',
  showTagline = true,
  align = 'left',
}: BrandMarkProps) {
  const [imageFailed, setImageFailed] = useState(false);
  const config = sizeConfig[size];
  const name = brand.name.trim() || 'GoAuth';
  const tagline = brand.tagline.trim();
  const iconURL = brand.icon_url.trim();
  const iconText = (brand.icon_text.trim() || name.charAt(0) || 'G').slice(0, 2).toUpperCase();
  const stacked = orientation === 'stacked';
  const showImage = Boolean(iconURL) && !imageFailed;

  useEffect(() => {
    setImageFailed(false);
  }, [iconURL]);

  const rootStyle: CSSProperties = {
    display: 'inline-flex',
    flexDirection: stacked ? 'column' : 'row',
    alignItems: 'center',
    justifyContent: align === 'center' ? 'center' : 'flex-start',
    gap: stacked ? config.gap : 10,
    textAlign: align === 'center' || stacked ? 'center' : 'left',
    minWidth: 0,
  };

  const iconStyle: CSSProperties = {
    width: config.icon,
    height: config.icon,
    flex: '0 0 auto',
    borderRadius: config.radius,
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'var(--ink)',
    color: 'var(--ink-inverse)',
    border: '1px solid var(--border-strong)',
    boxShadow: 'var(--shadow-sm)',
    overflow: 'hidden',
  };

  return (
    <div style={rootStyle} aria-label={name}>
      <div style={iconStyle}>
        {showImage ? (
          <img
            src={iconURL}
            alt=""
            referrerPolicy="no-referrer"
            onError={() => setImageFailed(true)}
            style={{
              width: '72%',
              height: '72%',
              objectFit: 'contain',
              filter: 'drop-shadow(0 0 1px rgba(0,0,0,0.35)) drop-shadow(0 0 1px rgba(255,255,255,0.35))',
            }}
          />
        ) : (
          <span style={{ fontSize: Math.max(12, Math.round(config.icon * 0.36)), fontWeight: 700, lineHeight: 1 }}>
            {iconText}
          </span>
        )}
      </div>
      <div style={{ minWidth: 0 }}>
        <div
          style={{
            fontSize: config.name,
            fontWeight: 650,
            lineHeight: 1.15,
            color: 'var(--ink)',
            overflowWrap: 'anywhere',
          }}
        >
          {name}
        </div>
        {showTagline && tagline && (
          <div
            style={{
              marginTop: 2,
              fontSize: config.tagline,
              lineHeight: 1.2,
              color: 'var(--ink-tertiary)',
              overflowWrap: 'anywhere',
            }}
          >
            {tagline}
          </div>
        )}
      </div>
    </div>
  );
}
