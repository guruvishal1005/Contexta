/**
 * CVE-specific API hooks
 */

import { useCallback } from 'react';
import { useApi, usePollingApi } from './useApi';
import { cvesApi, type CVE, type TrendingCVEsResponse, type CVEStats } from '@/lib/api';

/**
 * Hook for fetching CVEs
 */
export function useCVEs(params?: {
  page?: number;
  page_size?: number;
  severity?: string;
  min_cvss?: number;
  has_exploit?: boolean;
}) {
  const fetchCVEs = useCallback(() => cvesApi.list(params), [params]);
  return useApi<CVE[]>(fetchCVEs, [JSON.stringify(params)]);
}

/**
 * Hook for fetching trending CVEs with auto-refresh
 */
export function useTrendingCVEs(limit: number = 10, refreshInterval: number = 60000) {
  const fetchTrending = useCallback(() => cvesApi.getTrending(limit), [limit]);
  return usePollingApi<TrendingCVEsResponse>(fetchTrending, refreshInterval);
}

/**
 * Hook for CVE statistics
 */
export function useCVEStats() {
  const fetchStats = useCallback(() => cvesApi.getStats(), []);
  return useApi<CVEStats>(fetchStats);
}

/**
 * Hook for fetching a single CVE
 */
export function useCVE(id: string) {
  const fetchCVE = useCallback(() => cvesApi.getById(id), [id]);
  return useApi<CVE>(fetchCVE, [id]);
}
