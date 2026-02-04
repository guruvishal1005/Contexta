/**
 * Custom React Hooks for API Data Fetching
 */

import { useState, useEffect, useCallback } from 'react';

interface UseApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

interface UseApiResult<T> extends UseApiState<T> {
  refetch: () => Promise<void>;
}

/**
 * Generic hook for API data fetching
 */
export function useApi<T>(
  fetchFn: () => Promise<T>,
  dependencies: unknown[] = []
): UseApiResult<T> {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: true,
    error: null,
  });

  const fetchData = useCallback(async () => {
    setState(prev => ({ ...prev, loading: true, error: null }));
    try {
      const data = await fetchFn();
      setState({ data, loading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'An error occurred';
      setState({ data: null, loading: false, error });
    }
  }, [fetchFn]);

  useEffect(() => {
    fetchData();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, dependencies);

  return {
    ...state,
    refetch: fetchData,
  };
}

/**
 * Hook for polling data at intervals
 */
export function usePollingApi<T>(
  fetchFn: () => Promise<T>,
  intervalMs: number = 30000,
  dependencies: unknown[] = []
): UseApiResult<T> {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: true,
    error: null,
  });

  const fetchData = useCallback(async () => {
    try {
      const data = await fetchFn();
      setState({ data, loading: false, error: null });
    } catch (err) {
      const error = err instanceof Error ? err.message : 'An error occurred';
      setState(prev => ({ ...prev, loading: false, error }));
    }
  }, [fetchFn]);

  useEffect(() => {
    // Initial fetch
    fetchData();

    // Set up polling
    const interval = setInterval(fetchData, intervalMs);

    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, ...dependencies]);

  return {
    ...state,
    refetch: fetchData,
  };
}

/**
 * Hook for mutation operations (POST, PUT, DELETE)
 */
export function useMutation<T, P>(
  mutationFn: (params: P) => Promise<T>
): {
  mutate: (params: P) => Promise<T>;
  data: T | null;
  loading: boolean;
  error: string | null;
  reset: () => void;
} {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: false,
    error: null,
  });

  const mutate = useCallback(
    async (params: P): Promise<T> => {
      setState({ data: null, loading: true, error: null });
      try {
        const data = await mutationFn(params);
        setState({ data, loading: false, error: null });
        return data;
      } catch (err) {
        const error = err instanceof Error ? err.message : 'An error occurred';
        setState({ data: null, loading: false, error });
        throw err;
      }
    },
    [mutationFn]
  );

  const reset = useCallback(() => {
    setState({ data: null, loading: false, error: null });
  }, []);

  return {
    mutate,
    ...state,
    reset,
  };
}
