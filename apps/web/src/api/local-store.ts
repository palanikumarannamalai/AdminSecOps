import type { AssessmentResult } from './types';

/*
 * Optional, explicit, on-device persistence for the hosted application.
 * - Default: nothing is persisted; assessments live in memory and disappear on reload.
 * - Only when the visitor turns on "Keep assessments on this device" are PROCESSED results
 *   (never the raw evidence package) written to this browser's IndexedDB for this origin.
 * - "Delete local data" removes the database and the preference.
 * Nothing is ever sent to a server.
 */

const DB_NAME = 'adminsecops-hosted';
const STORE = 'assessments';
const PREFERENCE_KEY = 'adminsecops.keepAssessments';

export interface StoredAssessment {
  assessmentId: string;
  source: 'upload' | 'sample';
  result: AssessmentResult;
}

function storageAvailable(): boolean {
  return typeof indexedDB !== 'undefined';
}

export function readPersistencePreference(): boolean {
  try {
    return localStorage.getItem(PREFERENCE_KEY) === 'true';
  } catch {
    return false;
  }
}

function writePersistencePreference(enabled: boolean): void {
  try {
    if (enabled) localStorage.setItem(PREFERENCE_KEY, 'true');
    else localStorage.removeItem(PREFERENCE_KEY);
  } catch {
    // Storage may be unavailable (private browsing); persistence then stays off.
  }
}

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB request failed'));
  });
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE, { keyPath: 'assessmentId' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB could not be opened'));
  });
}

async function withStore<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb();
  try {
    return await request(fn(db.transaction(STORE, mode).objectStore(STORE)));
  } finally {
    db.close();
  }
}

export const localStore = {
  available: storageAvailable,
  async loadAll(): Promise<StoredAssessment[]> {
    if (!storageAvailable() || !readPersistencePreference()) return [];
    return withStore('readonly', (s) => s.getAll() as IDBRequest<StoredAssessment[]>);
  },
  async put(item: StoredAssessment): Promise<void> {
    if (!storageAvailable() || !readPersistencePreference()) return;
    await withStore('readwrite', (s) => s.put(item));
  },
  async remove(assessmentId: string): Promise<void> {
    if (!storageAvailable()) return;
    await withStore('readwrite', (s) => s.delete(assessmentId));
  },
  /** Turn persistence on (and save the given assessments) or off (and delete stored data). */
  async setEnabled(enabled: boolean, current: readonly StoredAssessment[]): Promise<void> {
    writePersistencePreference(enabled);
    if (!storageAvailable()) return;
    if (enabled) {
      for (const item of current) await withStore('readwrite', (s) => s.put(item));
    } else {
      await this.deleteAll();
    }
  },
  /** Remove the database and the preference. */
  async deleteAll(): Promise<void> {
    writePersistencePreference(false);
    if (!storageAvailable()) return;
    await new Promise<void>((resolve) => {
      const req = indexedDB.deleteDatabase(DB_NAME);
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
      req.onblocked = () => resolve();
    });
  },
};
