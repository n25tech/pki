import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, type Ca } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDate } from "../lib/files";
import { ErrorBox, Loading, Notice, StatusBadge } from "../components/ui";

export function Dashboard() {
  const { me } = useAuth();
  const [cas, setCas] = useState<Ca[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<{ cas: Ca[] }>("/cas")
      .then((r) => setCas(r.cas))
      .catch((e) => setError(e.message));
  }, []);

  if (error) return <ErrorBox error={error} />;
  if (!cas) return <Loading />;
  const roots = cas.filter((c) => c.kind === "root");

  return (
    <section>
      <div className="page-head">
        <h1>Certificate authorities</h1>
        <div className="row">
          {cas.some((c) => c.kind === "intermediate" && c.status === "valid") && (
            <Link className="button secondary" to="/certificates/new">
              Issue certificate
            </Link>
          )}
          <Link className="button" to="/cas/new">
            New root CA
          </Link>
        </div>
      </div>

      {me?.user && !me.user.emailVerified && (
        <Notice kind="info">
          Your email isn&rsquo;t verified yet. Check your inbox, or resend the link from <Link to="/account">your account</Link>.
        </Notice>
      )}

      {roots.length === 0 ? (
        <div className="empty">
          <h2>Create your first CA</h2>
          <p>
            Start with a root CA, limited to the private names you use (like <code>.home.arpa</code> or
            <code>.lan</code>). Then add an intermediate CA under it to issue certificates from.
          </p>
          <Link className="button" to="/cas/new">
            Create a root CA
          </Link>
        </div>
      ) : (
        <div className="tree">
          {roots.map((root) => (
            <div key={root.id} className="card">
              <div className="card-head">
                <div>
                  <Link to={`/cas/${root.id}`} className="card-title">
                    {root.name}
                  </Link>
                  <div className="muted small">
                    Root · {root.keyAlgorithm} · expires {formatDate(root.notAfter)}
                  </div>
                </div>
                <StatusBadge status={root.status} />
              </div>
              <div className="muted small">
                Allowed names: {[...(root.nameConstraints?.dns ?? []), ...(root.nameConstraints?.ip ?? [])].join(", ")}
              </div>
              <ul className="children">
                {cas
                  .filter((c) => c.parentId === root.id)
                  .map((inter) => (
                    <li key={inter.id}>
                      <Link to={`/cas/${inter.id}`}>{inter.name}</Link>{" "}
                      <span className="muted small">
                        {inter.certificates?.active ?? 0} active / {inter.certificates?.total ?? 0} issued · expires {formatDate(inter.notAfter)}
                      </span>{" "}
                      <StatusBadge status={inter.status} notAfter={inter.notAfter} />
                    </li>
                  ))}
                {!cas.some((c) => c.parentId === root.id) && (
                  <li className="muted">
                    No intermediate yet. <Link to={`/cas/${root.id}`}>Create one</Link> to start issuing certificates.
                  </li>
                )}
              </ul>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
