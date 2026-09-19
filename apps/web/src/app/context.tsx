import { createContext, use, type ReactNode } from 'react';
import { api as defaultApi, type ApiClient } from '../api/client';
import type { AssessmentListItem } from '../api/types';
import { useAsync, type AsyncResult } from '../hooks/useAsync';

interface AppContextValue {
  api: ApiClient;
  assessments: AsyncResult<AssessmentListItem[]>;
}

const AppContext = createContext<AppContextValue | null>(null);

export function AppProvider({ api = defaultApi, children }: { api?: ApiClient; children: ReactNode }) {
  const assessments = useAsync('assessments', (signal) => api.listAssessments(signal));
  return <AppContext value={{ api, assessments }}>{children}</AppContext>;
}

function useAppContext(): AppContextValue {
  const value = use(AppContext);
  if (value === null) throw new Error('AppProvider is missing');
  return value;
}

export function useApi(): ApiClient {
  return useAppContext().api;
}

/** Processed assessments known to the local service, newest first. */
export function useAssessmentList(): AsyncResult<AssessmentListItem[]> {
  return useAppContext().assessments;
}
