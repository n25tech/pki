import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, type Config, type Me } from "./api";

interface AuthState {
  me: Me | null;
  config: Config | null;
  refresh: () => Promise<Me>;
}

const AuthContext = createContext<AuthState>({ me: null, config: null, refresh: async () => ({ user: null }) });

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [config, setConfig] = useState<Config | null>(null);

  const refresh = useCallback(async () => {
    const next = await api<Me>("/auth/me").catch(() => ({ user: null }) as Me);
    setMe(next);
    return next;
  }, []);

  useEffect(() => {
    void refresh();
    api<Config>("/config").then(setConfig).catch(() => undefined);
  }, [refresh]);

  return <AuthContext.Provider value={{ me, config, refresh }}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);
