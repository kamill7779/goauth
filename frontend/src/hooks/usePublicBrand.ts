import { useEffect, useState } from 'react';
import { defaultPublicConfig, getPublicConfig } from '../api/publicConfig';
import type { PublicBrandConfig } from '../types/publicConfig';

export function usePublicBrand(): PublicBrandConfig {
  const [brand, setBrand] = useState<PublicBrandConfig>(defaultPublicConfig.brand);

  useEffect(() => {
    let cancelled = false;
    getPublicConfig()
      .then(config => {
        if (!cancelled) {
          setBrand(config.brand);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setBrand(defaultPublicConfig.brand);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return brand;
}
