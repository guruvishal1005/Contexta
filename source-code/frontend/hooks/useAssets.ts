/**
 * Asset-specific API hooks
 */

import { useCallback } from 'react';
import { useApi, useMutation } from './useApi';
import { assetsApi, type Asset, type AssetCreate, type AssetStats } from '@/lib/api';

/**
 * Hook for fetching assets
 */
export function useAssets(params?: {
  page?: number;
  page_size?: number;
  asset_type?: string;
  criticality?: string;
}) {
  const fetchAssets = useCallback(() => assetsApi.list(params), [params]);
  return useApi<Asset[]>(fetchAssets, [JSON.stringify(params)]);
}

/**
 * Hook for fetching a single asset
 */
export function useAsset(id: string) {
  const fetchAsset = useCallback(() => assetsApi.getById(id), [id]);
  return useApi<Asset>(fetchAsset, [id]);
}

/**
 * Hook for asset statistics
 */
export function useAssetStats() {
  const fetchStats = useCallback(() => assetsApi.getStats(), []);
  return useApi<AssetStats>(fetchStats);
}

/**
 * Hook for creating an asset
 */
export function useCreateAsset() {
  return useMutation<Asset, AssetCreate>(assetsApi.create);
}
