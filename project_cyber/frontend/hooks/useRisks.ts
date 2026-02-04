/**
 * Risk-specific API hooks
 */

import { useCallback } from 'react';
import { useApi, usePollingApi } from './useApi';
import { risksApi, type Risk, type TopRisksResponse, type RiskStats } from '@/lib/api';

/**
 * Hook for fetching top 10 risks with auto-refresh
 */
export function useTopRisks(refreshInterval: number = 30000) {
  const fetchTopRisks = useCallback(() => risksApi.getTop10(), []);
  return usePollingApi<TopRisksResponse>(fetchTopRisks, refreshInterval);
}

/**
 * Hook for fetching all risks
 */
export function useRisks(params?: {
  page?: number;
  page_size?: number;
  status?: string;
  min_bwvs?: number;
}) {
  const fetchRisks = useCallback(() => risksApi.list(params), [params]);
  return useApi<Risk[]>(fetchRisks, [JSON.stringify(params)]);
}

/**
 * Hook for fetching risk by ID
 */
export function useRisk(id: string) {
  const fetchRisk = useCallback(() => risksApi.getById(id), [id]);
  return useApi<Risk>(fetchRisk, [id]);
}

/**
 * Hook for fetching risk statistics
 */
export function useRiskStats() {
  const fetchStats = useCallback(() => risksApi.getStats(), []);
  return useApi<RiskStats>(fetchStats);
}
