import { useCallback, useEffect, useEffectEvent, useState } from 'react';

export type AsyncState<T> =
  | { status: 'loading'; data: undefined; error: undefined }
  | { status: 'success'; data: T; error: undefined }
  | { status: 'error'; data: undefined; error: unknown };

export type AsyncResult<T> = AsyncState<T> & { reload: () => void };

type Settled<T> = { key: string } & AsyncState<T>;

const LOADING = { status: 'loading', data: undefined, error: undefined } as const;

/**
 * Runs `load` whenever `key` changes (or `reload` is called) and exposes the
 * loading / success / error state. Pass `null` as key to skip loading. In-flight
 * requests are aborted when the key changes or the component unmounts.
 */
export function useAsync<T>(key: string | null, load: (signal: AbortSignal) => Promise<T>): AsyncResult<T> {
  const [generation, setGeneration] = useState(0);
  const [settled, setSettled] = useState<Settled<T> | null>(null);
  const requestKey = key === null ? null : `${generation}:${key}`;
  const run = useEffectEvent((signal: AbortSignal) => load(signal));

  useEffect(() => {
    if (requestKey === null) return;
    const controller = new AbortController();
    run(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setSettled({ key: requestKey, status: 'success', data, error: undefined });
      },
      (error: unknown) => {
        if (!controller.signal.aborted) setSettled({ key: requestKey, status: 'error', data: undefined, error });
      },
    );
    return () => controller.abort();
  }, [requestKey]);

  const reload = useCallback(() => setGeneration((g) => g + 1), []);

  if (settled === null || settled.key !== requestKey) return { ...LOADING, reload };
  if (settled.status === 'success') return { status: 'success', data: settled.data, error: undefined, reload };
  if (settled.status === 'error') return { status: 'error', data: undefined, error: settled.error, reload };
  return { ...LOADING, reload };
}
