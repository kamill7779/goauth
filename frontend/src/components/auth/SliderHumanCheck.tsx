import { PointerEvent, useCallback, useEffect, useRef, useState } from 'react'
import { getSliderChallenge, verifySliderChallenge, type SliderChallenge, type SliderTrackPoint } from '../../api/humanCheck'

interface SliderHumanCheckProps {
  enabled: boolean
  token: string
  onToken: (token: string) => void
  onError: (message: string) => void
}

type DragState = {
  pointerId: number
  startClientX: number
  startClientY: number
  startTime: number
}

export default function SliderHumanCheck({ enabled, token, onToken, onError }: SliderHumanCheckProps) {
  const [challenge, setChallenge] = useState<SliderChallenge | null>(null)
  const [loading, setLoading] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [offset, setOffset] = useState(0)
  const [renderedWidth, setRenderedWidth] = useState(0)
  const [drag, setDrag] = useState<DragState | null>(null)
  const imageFrameRef = useRef<HTMLDivElement | null>(null)
  const offsetRef = useRef(0)
  const trackRef = useRef<SliderTrackPoint[]>([])

  const challengeWidth = challenge?.width ?? 320
  const safeRenderedWidth = renderedWidth > 0 ? renderedWidth : challengeWidth
  const maxOffset = Math.max(1, challengeXToDisplayOffset((challenge?.width ?? 320) - (challenge?.thumb_width ?? 42), safeRenderedWidth, challengeWidth))
  const progress = token ? 100 : Math.round((offset / maxOffset) * 100)
  const thumbDisplayWidth = challenge ? challengeXToDisplayOffset(challenge.thumb_width, safeRenderedWidth, challenge.width) : 42
  const thumbDisplayHeight = challenge ? challengeXToDisplayOffset(challenge.thumb_height, safeRenderedWidth, challenge.width) : 42
  const thumbDisplayY = challenge ? challengeXToDisplayOffset(challenge.thumb_y, safeRenderedWidth, challenge.width) : 0

  const resetChallenge = useCallback(async () => {
    if (!enabled) {
      return
    }
    setLoading(true)
    setOffset(0)
    offsetRef.current = 0
    trackRef.current = []
    try {
      const next = await getSliderChallenge()
      setChallenge(next)
    } catch (err) {
      onError(err instanceof Error ? err.message : '安全验证加载失败')
    } finally {
      setLoading(false)
    }
  }, [enabled, onError])

  useEffect(() => {
    if (!enabled) {
      setChallenge(null)
      setOffset(0)
      offsetRef.current = 0
      return
    }
    if (!token) {
      void resetChallenge()
    }
  }, [enabled, resetChallenge, token])

  useEffect(() => {
    if (!challenge || !imageFrameRef.current) {
      setRenderedWidth(0)
      return
    }

    const frame = imageFrameRef.current
    const updateRenderedWidth = () => {
      setRenderedWidth(frame.getBoundingClientRect().width)
    }

    updateRenderedWidth()
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', updateRenderedWidth)
      return () => window.removeEventListener('resize', updateRenderedWidth)
    }

    const observer = new ResizeObserver(updateRenderedWidth)
    observer.observe(frame)
    return () => observer.disconnect()
  }, [challenge])

  const complete = useCallback(async (finalOffset: number) => {
    if (!challenge || token) {
      return
    }
    setVerifying(true)
    try {
      const elapsed = lastTrackPoint(trackRef.current)?.t ?? 0
      const result = await verifySliderChallenge({
        challenge_id: challenge.id,
        nonce: challenge.nonce,
        x: displayOffsetToChallengeX(finalOffset, safeRenderedWidth, challenge.width),
        y: challenge.thumb_y,
        elapsed_ms: elapsed,
        track: trackRef.current,
      })
      onToken(result.token)
    } catch (err) {
      setOffset(0)
      offsetRef.current = 0
      trackRef.current = []
      onError(err instanceof Error ? err.message : '安全验证失败，请重试')
      void resetChallenge()
    } finally {
      setVerifying(false)
    }
  }, [challenge, onError, onToken, resetChallenge, token])

  const onPointerDown = useCallback((event: PointerEvent<HTMLButtonElement>) => {
    if (!challenge || token || loading || verifying) {
      return
    }
    const startedAt = performance.now()
    setDrag({
      pointerId: event.pointerId,
      startClientX: event.clientX - offset,
      startClientY: event.clientY,
      startTime: startedAt,
    })
    offsetRef.current = offset
    trackRef.current = [{
      x: displayOffsetToChallengeX(offset, safeRenderedWidth, challenge.width),
      y: challenge.thumb_y,
      t: 0,
    }]
    event.currentTarget.setPointerCapture(event.pointerId)
  }, [challenge, loading, offset, safeRenderedWidth, token, verifying])

  const onPointerMove = useCallback((event: PointerEvent<HTMLButtonElement>) => {
    if (!drag || !challenge || event.pointerId !== drag.pointerId) {
      return
    }
    const nextOffset = clamp(event.clientX - drag.startClientX, 0, maxOffset)
    setOffset(nextOffset)
    offsetRef.current = nextOffset
    trackRef.current.push({
      x: displayOffsetToChallengeX(nextOffset, safeRenderedWidth, challenge.width),
      y: Math.round(challenge.thumb_y + (event.clientY - drag.startClientY) / displayScale(safeRenderedWidth, challenge.width)),
      t: Math.round(performance.now() - drag.startTime),
    })
  }, [challenge, drag, maxOffset, safeRenderedWidth])

  const onPointerUp = useCallback((event: PointerEvent<HTMLButtonElement>) => {
    if (!drag || event.pointerId !== drag.pointerId) {
      return
    }
    setDrag(null)
    event.currentTarget.releasePointerCapture(event.pointerId)
    void complete(offsetRef.current)
  }, [complete, drag])

  if (!enabled) {
    return null
  }

  return (
    <div style={containerStyle}>
      <div style={titleRowStyle}>
        <div>
          <div style={titleStyle}>拖动完成安全验证</div>
          <div style={hintStyle}>{token ? '已通过验证' : '请把滑块拖到图中缺口位置'}</div>
        </div>
        <button type="button" onClick={resetChallenge} disabled={loading || verifying} style={refreshStyle}>
          换一张
        </button>
      </div>

      <div ref={imageFrameRef} style={{ ...imageFrameStyle, aspectRatio: challenge ? `${challenge.width} / ${challenge.height}` : '2 / 1' }}>
        {challenge ? (
          <>
            <img src={challenge.image} alt="" draggable={false} style={imageStyle} />
            <img
              src={challenge.thumb}
              alt=""
              draggable={false}
              style={{
                ...thumbImageStyle,
                width: `${thumbDisplayWidth}px`,
                height: `${thumbDisplayHeight}px`,
                transform: `translate(${offset}px, ${thumbDisplayY}px)`,
              }}
            />
          </>
        ) : (
          <div style={loadingStyle}>{loading ? '加载验证...' : '准备安全验证'}</div>
        )}
      </div>

      <div style={railStyle}>
        <div style={{ ...railFillStyle, width: `${progress}%` }} />
        <span style={railTextStyle}>{token ? '验证通过' : verifying ? '验证中...' : '按住滑块向右拖动'}</span>
        <button
          type="button"
          role="slider"
          aria-label="拖动安全验证"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={progress}
          aria-disabled={Boolean(token || loading || verifying)}
          disabled={Boolean(token || loading || verifying)}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerCancel={onPointerUp}
          style={{
            ...handleStyle,
            transform: `translateX(${Math.round(offset)}px)`,
            cursor: token || loading || verifying ? 'default' : 'grab',
          }}
        >
          {token ? '✓' : '→'}
        </button>
      </div>
    </div>
  )
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value))
}

function displayScale(renderedWidth: number, challengeWidth: number): number {
  if (renderedWidth <= 0 || challengeWidth <= 0) {
    return 1
  }
  return renderedWidth / challengeWidth
}

export function displayOffsetToChallengeX(displayOffset: number, renderedWidth: number, challengeWidth: number): number {
  return Math.round(displayOffset / displayScale(renderedWidth, challengeWidth))
}

export function challengeXToDisplayOffset(challengeX: number, renderedWidth: number, challengeWidth: number): number {
  return challengeX * displayScale(renderedWidth, challengeWidth)
}

function lastTrackPoint(track: SliderTrackPoint[]): SliderTrackPoint | undefined {
  return track.length > 0 ? track[track.length - 1] : undefined
}

const containerStyle: React.CSSProperties = {
  margin: '0 0 18px',
  padding: '14px',
  border: '1px solid var(--border)',
  borderRadius: '16px',
  background: 'var(--surface-hover)',
}

const titleRowStyle: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  gap: '12px',
  alignItems: 'center',
  marginBottom: '12px',
}

const titleStyle: React.CSSProperties = {
  fontSize: '13px',
  fontWeight: 600,
  color: 'var(--ink)',
}

const hintStyle: React.CSSProperties = {
  marginTop: '3px',
  fontSize: '12px',
  color: 'var(--ink-secondary)',
}

const refreshStyle: React.CSSProperties = {
  border: 'none',
  background: 'transparent',
  color: 'var(--accent)',
  cursor: 'pointer',
  fontSize: '12px',
  fontWeight: 600,
  padding: '4px',
}

const imageFrameStyle: React.CSSProperties = {
  position: 'relative',
  overflow: 'hidden',
  borderRadius: '14px',
  background: 'var(--surface-solid)',
  userSelect: 'none',
}

const imageStyle: React.CSSProperties = {
  width: '100%',
  height: '100%',
  objectFit: 'cover',
  display: 'block',
}

const thumbImageStyle: React.CSSProperties = {
  position: 'absolute',
  top: 0,
  left: 0,
  filter: 'drop-shadow(0 8px 16px rgba(0,0,0,.18))',
  transition: 'filter .2s ease',
  touchAction: 'none',
}

const loadingStyle: React.CSSProperties = {
  height: '120px',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  color: 'var(--ink-secondary)',
  fontSize: '13px',
}

const railStyle: React.CSSProperties = {
  position: 'relative',
  height: '42px',
  marginTop: '12px',
  borderRadius: '999px',
  background: 'var(--surface-solid)',
  border: '1px solid var(--border)',
  overflow: 'hidden',
}

const railFillStyle: React.CSSProperties = {
  position: 'absolute',
  top: 0,
  bottom: 0,
  left: 0,
  background: 'color-mix(in srgb, var(--accent) 18%, transparent)',
  transition: 'width .12s ease',
}

const railTextStyle: React.CSSProperties = {
  position: 'absolute',
  inset: 0,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  color: 'var(--ink-secondary)',
  fontSize: '12px',
  pointerEvents: 'none',
}

const handleStyle: React.CSSProperties = {
  position: 'absolute',
  top: '3px',
  left: '3px',
  width: '34px',
  height: '34px',
  borderRadius: '999px',
  border: 'none',
  background: 'var(--accent)',
  color: 'var(--ink-inverse)',
  fontSize: '18px',
  fontWeight: 700,
  boxShadow: '0 6px 16px var(--accent-glow)',
  touchAction: 'none',
  zIndex: 2,
}
