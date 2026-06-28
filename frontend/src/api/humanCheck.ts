import { apiGet, apiPost } from './client';

export interface SliderChallenge {
  id: string;
  nonce: string;
  thumb_x: number;
  thumb_y: number;
  thumb_width: number;
  thumb_height: number;
  width: number;
  height: number;
  image: string;
  thumb: string;
}

export interface SliderTrackPoint {
  x: number;
  y: number;
  t: number;
}

export interface VerifySliderInput {
  challenge_id: string;
  nonce: string;
  x: number;
  y: number;
  elapsed_ms: number;
  track: SliderTrackPoint[];
}

export interface HumanCheckToken {
  token: string;
  expires_at: string;
}

export async function getSliderChallenge(): Promise<SliderChallenge> {
  return apiGet<SliderChallenge>('/human-check/slider');
}

export async function verifySliderChallenge(input: VerifySliderInput): Promise<HumanCheckToken> {
  return apiPost<HumanCheckToken>('/human-check/slider/verify', input);
}
