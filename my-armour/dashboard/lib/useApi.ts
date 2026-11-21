"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError } from "./api";

interface State<T> {
  key: string | null;
  data?: T;
  error?: ApiError;
}

/**
 * Fetch data for a client component. Re-runs when `key` changes (encode every
 * input of the fetcher in it). While a new key loads, the previous data stays
 * visible (`loading` is true) so charts don't flash empty on a filter change.
 */
export function useApi<T>(key: string, fetcher: () => Promise<T>) {
  const fetcherRef = useRef(fetcher);
  const [nonce, setNonce] = useState(0);
  const [state, setState] = useState<State<T>>({ key: null });
  const requestKey = `${key}#${nonce}`;

  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  useEffect(() => {
    let cancelled = false;
    fetcherRef.current().then(
      (data) => !cancelled && setState({ key: requestKey, data }),
      (error: unknown) =>
        !cancelled &&
        setState((previous) => ({
          key: requestKey,
          data: previous.data,
          error: error instanceof ApiError ? error : new ApiError(0, String(error)),
        })),
    );
    return () => {
      cancelled = true;
    };
  }, [requestKey]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const loading = state.key !== requestKey;
  return {
    data: state.data,
    error: loading ? undefined : state.error,
    loading,
    reload,
    setData: (data: T) => setState({ key: requestKey, data }),
  };
}
