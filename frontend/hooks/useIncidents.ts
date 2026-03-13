/**
 * Incident-specific API hooks
 */

import { useCallback } from 'react';
import { useApi, useMutation } from './useApi';
import { incidentsApi, type Incident, type IncidentCreate, type IncidentUpdate } from '@/lib/api';

/**
 * Hook for fetching incidents
 */
export function useIncidents(params?: {
  page?: number;
  page_size?: number;
  status_filter?: string;
  severity_filter?: string;
}) {
  const fetchIncidents = useCallback(() => incidentsApi.list(params), [params]);
  return useApi<Incident[]>(fetchIncidents, [JSON.stringify(params)]);
}

/**
 * Hook for fetching a single incident
 */
export function useIncident(id: string) {
  const fetchIncident = useCallback(() => incidentsApi.getById(id), [id]);
  return useApi<Incident>(fetchIncident, [id]);
}

/**
 * Hook for creating an incident
 */
export function useCreateIncident() {
  return useMutation<Incident, IncidentCreate>(incidentsApi.create);
}

/**
 * Hook for updating an incident
 */
export function useUpdateIncident(id: string) {
  const updateFn = useCallback(
    (data: IncidentUpdate) => incidentsApi.update(id, data),
    [id]
  );
  return useMutation<Incident, IncidentUpdate>(updateFn);
}
