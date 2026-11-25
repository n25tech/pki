/**
 * Root private keys unlocked in this tab. Kept only in memory: they're gone on
 * reload, and never sent anywhere.
 */
import { useSyncExternalStore } from "react";

const keys = new Map<string, CryptoKey>();
const listeners = new Set<() => void>();
let version = 0;

function emit() {
  version++;
  listeners.forEach((l) => l());
}

export const rootKeys = {
  get: (id: string) => keys.get(id),
  set(id: string, key: CryptoKey) {
    keys.set(id, key);
    emit();
  },
  forget(id: string) {
    keys.delete(id);
    emit();
  },
};

export function useRootKey(id: string | undefined): CryptoKey | undefined {
  useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => version,
  );
  return id ? keys.get(id) : undefined;
}
