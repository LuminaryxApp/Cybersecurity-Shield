import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { alertsApi, agentsApi, eventsApi, metricsApi } from '../api/endpoints'

export function useAlerts(params?: { severity?: string; status?: string }) {
  return useQuery({
    queryKey: ['alerts', params],
    queryFn: () => alertsApi.list(params),
    refetchInterval: 10000,
  })
}

export function useAlert(id: string) {
  return useQuery({
    queryKey: ['alert', id],
    queryFn: () => alertsApi.get(id),
    enabled: !!id,
  })
}

export function useUpdateAlertStatus() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      alertsApi.updateStatus(id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })
}

export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: () => agentsApi.list(),
    refetchInterval: 15000,
  })
}

export function useAgent(id: string) {
  return useQuery({
    queryKey: ['agent', id],
    queryFn: () => agentsApi.get(id),
    enabled: !!id,
  })
}

export function useEvents(params?: { source?: string; category?: string; severity?: string }) {
  return useQuery({
    queryKey: ['events', params],
    queryFn: () => eventsApi.list(params),
    refetchInterval: 10000,
  })
}

export function useThreatScore(orgId: string) {
  return useQuery({
    queryKey: ['threatScore', orgId],
    queryFn: () => metricsApi.getThreatScore(orgId),
    refetchInterval: 30000,
    enabled: !!orgId,
  })
}

export function useMetrics(name: string, range?: string) {
  return useQuery({
    queryKey: ['metrics', name, range],
    queryFn: () => metricsApi.queryMetrics(name, range),
    refetchInterval: 30000,
    enabled: !!name,
  })
}
