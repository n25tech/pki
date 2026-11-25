import { lazy, Suspense } from "react";
import { BrowserRouter, Link, Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate } from "react-router";
import { api } from "./lib/api";
import { AuthProvider, useAuth } from "./lib/auth";
import { Loading } from "./components/ui";
import { ForgotPassword, Login, MfaChallenge, Register, ResetPassword, SetupTwoFactor, VerifyEmail } from "./pages/auth";
import { Dashboard } from "./pages/dashboard";
import { Inventory } from "./pages/inventory";
import { CertificateDetail } from "./pages/certificateDetail";
import { Lookup } from "./pages/lookup";
import { TrustGuide } from "./pages/trust";
import { Account } from "./pages/account";
import { Legal } from "./pages/legal";

// Pages that do X.509 work in the browser load the crypto libraries on demand.
const NewRoot = lazy(() => import("./pages/newRoot").then((m) => ({ default: m.NewRoot })));
const CaDetail = lazy(() => import("./pages/caDetail").then((m) => ({ default: m.CaDetail })));
const IssueCertificate = lazy(() => import("./pages/issue").then((m) => ({ default: m.IssueCertificate })));

export function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/login/mfa" element={<MfaChallenge />} />
            <Route path="/forgot-password" element={<ForgotPassword />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route path="/verify-email" element={<VerifyEmail />} />
            <Route path="/legal" element={<Legal />} />
            <Route path="/trust" element={<TrustGuide />} />

            <Route element={<RequireStage stages={["setup", "full"]} />}>
              <Route path="/setup-2fa" element={<SetupTwoFactor />} />
              <Route path="/account" element={<Account />} />
            </Route>

            <Route element={<RequireStage stages={["full"]} />}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/cas/new" element={<NewRoot />} />
              <Route path="/cas/:id" element={<CaDetail />} />
              <Route path="/certificates" element={<Inventory />} />
              <Route path="/certificates/new" element={<IssueCertificate />} />
              <Route path="/certificates/:id" element={<CertificateDetail />} />
              <Route path="/lookup" element={<Lookup />} />
            </Route>

            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

/** Sends people to sign in, enter their code, or set up 2FA as needed. */
function RequireStage({ stages }: { stages: Array<"setup" | "full"> }) {
  const { me } = useAuth();
  const location = useLocation();
  if (!me) return <Loading />;
  if (!me.user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  if (me.stage === "mfa") return <Navigate to="/login/mfa" replace />;
  if (me.stage === "setup" && !stages.includes("setup")) return <Navigate to="/setup-2fa" replace />;
  return <Outlet />;
}

function Layout() {
  const { me, refresh } = useAuth();
  const navigate = useNavigate();
  const full = me?.stage === "full";

  async function signOut() {
    await api("/auth/logout", { json: {} });
    await refresh();
    navigate("/login");
  }

  return (
    <div className="shell">
      <header className="topbar">
        <Link to="/" className="brand">
          Private PKI
        </Link>
        {full && (
          <nav className="nav">
            <NavLink to="/" end>
              CAs
            </NavLink>
            <NavLink to="/certificates">Certificates</NavLink>
            <NavLink to="/lookup">Lookup</NavLink>
            <NavLink to="/trust">Trust guide</NavLink>
          </nav>
        )}
        <div className="nav-right">
          {me?.user ? (
            <>
              <NavLink to="/account" className="muted">
                {me.user.email}
              </NavLink>
              <button type="button" className="link" onClick={signOut}>
                Sign out
              </button>
            </>
          ) : (
            me && <NavLink to="/login">Sign in</NavLink>
          )}
        </div>
      </header>
      <main className="content">
        <Suspense fallback={<Loading />}>
          <Outlet />
        </Suspense>
      </main>
      <footer className="footer">
        <span>Not a production PKI. For anything security-critical, use Let&rsquo;s Encrypt.</span>
        <Link to="/legal">Disclaimer, terms &amp; privacy</Link>
        <a href="https://github.com/n25tech/pki">Source</a>
      </footer>
    </div>
  );
}

function NotFound() {
  return (
    <section>
      <h1>Page not found</h1>
      <p>
        <Link to="/">Go to your CAs</Link>
      </p>
    </section>
  );
}
