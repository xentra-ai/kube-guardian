// Lazy-import with one automatic recovery from a stale deployment.
//
// Every code-split chunk is content-hashed, so a redeploy changes the file
// names. A tab that was opened before the deploy still holds the old
// `index-*.js`, and the first time it opens a surface it has not loaded yet
// (the audit panel, the policy builder, ...) the dynamic import asks the new
// pod for a chunk that no longer exists → 404 → "Failed to fetch dynamically
// imported module". Without this, that surface silently never appears.
//
// Recovery: reload the page once so it picks up the current index and chunk
// set. The guard in sessionStorage stops a genuine outage (chunk really
// missing after a fresh load) from turning into a reload loop — the second
// failure is rethrown to the error boundary like any other error.

import { lazy, type ComponentType, type LazyExoticComponent } from 'react';

const RELOAD_GUARD_KEY = 'kguardian.chunk-reload';

/** True for the errors browsers raise when a dynamic `import()` cannot be fetched. */
export function isChunkLoadError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const msg = err.message || '';
  return (
    /dynamically imported module/i.test(msg) ||
    /Loading chunk [\w-]+ failed/i.test(msg) ||
    /Importing a module script failed/i.test(msg) ||
    err.name === 'ChunkLoadError'
  );
}

/**
 * Pure decision: given the error and whether a reload was already attempted
 * this session, should we reload? Exposed for tests; `lazyRetry` wires it to
 * `sessionStorage` and `location.reload()`.
 */
export function shouldReloadForChunkError(err: unknown, alreadyReloaded: boolean): boolean {
  return isChunkLoadError(err) && !alreadyReloaded;
}

function readGuard(): boolean {
  try {
    return sessionStorage.getItem(RELOAD_GUARD_KEY) === '1';
  } catch {
    return false;
  }
}

function writeGuard(): void {
  try {
    sessionStorage.setItem(RELOAD_GUARD_KEY, '1');
  } catch {
    // Storage blocked: fall through to a plain reload; the worst case is one
    // extra reload, never a loop, because the import either succeeds or the
    // error boundary shows it.
  }
}

/** Clear the guard once a chunk loads, so a later deploy can recover again. */
function clearGuard(): void {
  try {
    sessionStorage.removeItem(RELOAD_GUARD_KEY);
  } catch {
    /* ignore */
  }
}

export interface RetryHooks {
  readGuard: () => boolean;
  writeGuard: () => void;
  clearGuard: () => void;
  reload: () => void;
}

const browserHooks: RetryHooks = {
  readGuard,
  writeGuard,
  clearGuard,
  reload: () => window.location.reload(),
};

/**
 * The import wrapper itself, separated from `lazy()` so it can be tested
 * without React's internals: resolves the module, or reloads once on a
 * stale-chunk failure (returning a never-settling promise so Suspense stays
 * pending through the reload), or rethrows.
 */
export function retryingImport<M>(factory: () => Promise<M>, hooks: RetryHooks = browserHooks): Promise<M> {
  return factory().then(
    (mod) => {
      hooks.clearGuard();
      return mod;
    },
    (err: unknown) => {
      if (shouldReloadForChunkError(err, hooks.readGuard())) {
        hooks.writeGuard();
        hooks.reload();
        return new Promise<M>(() => {});
      }
      throw err;
    },
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- mirrors React.lazy's own signature
export function lazyRetry<T extends ComponentType<any>>(
  factory: () => Promise<{ default: T }>,
): LazyExoticComponent<T> {
  return lazy(() => retryingImport(factory));
}
