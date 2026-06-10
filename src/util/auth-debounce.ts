/**
 * Debounces interactive authentication (browser login, ROPC prompts) so
 * Insomnia's live preview while editing string tag arguments — especially
 * Token scope — does not open a new browser tab on every keystroke.
 *
 * Callers still return cached tokens immediately; only cache misses wait
 * for a short quiet period before the producer runs. Rapid edits to the
 * same tag instance coalesce onto one producer invocation (latest args win).
 */

import { withInflightLock } from "./token-cache";

/** Quiet period after the last config change before auth starts. */
export const DEFAULT_INTERACTIVE_AUTH_DELAY_MS = 1000;

interface Slot {
  timer: ReturnType<typeof setTimeout>;
  latestCacheKey: string;
  latestProducer: () => Promise<string>;
  deferred: {
    promise: Promise<string>;
    resolve: (value: string) => void;
    reject: (reason: unknown) => void;
  };
}

const slots = new Map<string, Slot>();

function createSlot(cacheKey: string, producer: () => Promise<string>): Slot {
  let resolve!: (value: string) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<string>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return {
    timer: setTimeout(() => {}, 0),
    latestCacheKey: cacheKey,
    latestProducer: producer,
    deferred: { promise, resolve, reject },
  };
}

async function flushSlot(groupKey: string): Promise<void> {
  const slot = slots.get(groupKey);
  if (!slot) return;
  slots.delete(groupKey);

  const { latestCacheKey, latestProducer, deferred } = slot;
  try {
    const result = await withInflightLock(latestCacheKey, latestProducer);
    deferred.resolve(result);
  } catch (err) {
    deferred.reject(err);
  }
}

/**
 * Waits until tag configuration has been stable for `delayMs`, then runs
 * `producer` once per burst (latest `cacheKey` wins). Concurrent callers
 * for the same `groupKey` share the same returned promise.
 */
export function scheduleInteractiveAuth(
  groupKey: string,
  cacheKey: string,
  producer: () => Promise<string>,
  delayMs = DEFAULT_INTERACTIVE_AUTH_DELAY_MS,
): Promise<string> {
  let slot = slots.get(groupKey);
  if (!slot) {
    slot = createSlot(cacheKey, producer);
    slots.set(groupKey, slot);
  } else {
    slot.latestCacheKey = cacheKey;
    slot.latestProducer = producer;
    clearTimeout(slot.timer);
  }

  slot.timer = setTimeout(() => {
    void flushSlot(groupKey);
  }, delayMs);

  return slot.deferred.promise;
}

export const __testReset = (): void => {
  for (const slot of slots.values()) {
    clearTimeout(slot.timer);
  }
  slots.clear();
};
