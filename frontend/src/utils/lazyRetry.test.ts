import { describe, it, expect } from 'vitest';
import { isChunkLoadError, shouldReloadForChunkError, lazyRetry, retryingImport } from './lazyRetry';

describe('isChunkLoadError', () => {
  it('recognises the browsers\' dynamic-import failures', () => {
    expect(isChunkLoadError(new TypeError('Failed to fetch dynamically imported module: https://x/assets/AuditVerdictsPanel-abc.js'))).toBe(true);
    expect(isChunkLoadError(new Error('Loading chunk 42 failed'))).toBe(true);
    expect(isChunkLoadError(new TypeError('Importing a module script failed.'))).toBe(true);
    const named = new Error('x');
    named.name = 'ChunkLoadError';
    expect(isChunkLoadError(named)).toBe(true);
  });

  it('leaves other errors alone', () => {
    expect(isChunkLoadError(new Error('boom'))).toBe(false);
    expect(isChunkLoadError('Failed to fetch dynamically imported module')).toBe(false);
    expect(isChunkLoadError(undefined)).toBe(false);
  });
});

describe('shouldReloadForChunkError', () => {
  const chunkErr = new TypeError('Failed to fetch dynamically imported module: /assets/x.js');
  it('reloads once for a chunk error', () => {
    expect(shouldReloadForChunkError(chunkErr, false)).toBe(true);
  });
  it('never reloads twice in a session (no reload loop on a real outage)', () => {
    expect(shouldReloadForChunkError(chunkErr, true)).toBe(false);
  });
  it('does not reload for an unrelated error', () => {
    expect(shouldReloadForChunkError(new Error('render bug'), false)).toBe(false);
  });
});

describe('retryingImport', () => {
  const mkHooks = (already: boolean) => {
    const state = { guard: already, reloads: 0 };
    return {
      state,
      hooks: {
        readGuard: () => state.guard,
        writeGuard: () => {
          state.guard = true;
        },
        clearGuard: () => {
          state.guard = false;
        },
        reload: () => {
          state.reloads += 1;
        },
      },
    };
  };
  const stale = () => Promise.reject(new TypeError('Failed to fetch dynamically imported module: /assets/old.js'));

  it('reloads the page once on a stale-chunk failure and keeps the import pending', async () => {
    const { state, hooks } = mkHooks(false);
    let settled = false;
    void retryingImport(stale, hooks).then(() => { settled = true; }, () => { settled = true; });
    await new Promise((r) => setTimeout(r, 10));
    expect(state.reloads).toBe(1);
    expect(state.guard).toBe(true);
    expect(settled).toBe(false);
  });

  it('rethrows on a second failure in the same session (no reload loop on a real outage)', async () => {
    const { state, hooks } = mkHooks(true);
    await expect(retryingImport(stale, hooks)).rejects.toThrow(/dynamically imported module/);
    expect(state.reloads).toBe(0);
  });

  it('rethrows non-chunk errors without reloading', async () => {
    const { state, hooks } = mkHooks(false);
    await expect(retryingImport(() => Promise.reject(new Error('render bug')), hooks)).rejects.toThrow('render bug');
    expect(state.reloads).toBe(0);
  });

  it('clears the guard once a chunk loads so a later deploy can recover again', async () => {
    const { state, hooks } = mkHooks(true);
    const mod = await retryingImport(() => Promise.resolve({ default: () => null }), hooks);
    expect(mod.default).toBeTypeOf('function');
    expect(state.guard).toBe(false);
  });

  it('is what lazyRetry wraps', () => {
    const Comp = lazyRetry(() => Promise.resolve({ default: () => null }));
    expect(Comp).toBeTruthy();
  });
});
