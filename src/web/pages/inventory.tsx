import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api, type Ca, type Certificate } from "../lib/api";
import { formatDate } from "../lib/files";
import { ErrorBox, Loading, StatusBadge } from "../components/ui";

export function Inventory() {
  const [params, setParams] = useSearchParams();
  const [certs, setCerts] = useState<Certificate[] | null>(null);
  const [cas, setCas] = useState<Map<string, Ca>>(new Map());
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState(params.get("q") ?? "");

  useEffect(() => {
    api<{ cas: Ca[] }>("/cas").then((r) => setCas(new Map(r.cas.map((c) => [c.id, c]))));
  }, []);

  useEffect(() => {
    const t = setTimeout(() => {
      api<{ certificates: Certificate[] }>(`/certificates?${params.toString()}`)
        .then((r) => setCerts(r.certificates))
        .catch((e) => setError(e.message));
    }, 150);
    return () => clearTimeout(t);
  }, [params]);

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  return (
    <section>
      <div className="page-head">
        <h1>Certificates</h1>
        <Link className="button" to="/certificates/new">
          Issue certificate
        </Link>
      </div>
      <div className="filters">
        <input
          type="search"
          placeholder="Search names, serials, notes…"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setParam("q", e.target.value);
          }}
        />
        <select value={params.get("status") ?? ""} onChange={(e) => setParam("status", e.target.value)}>
          <option value="">All statuses</option>
          <option value="valid">Valid</option>
          <option value="expiring">Expiring in 30 days</option>
          <option value="expired">Expired</option>
          <option value="revoked">Revoked</option>
        </select>
        <select value={params.get("caId") ?? ""} onChange={(e) => setParam("caId", e.target.value)}>
          <option value="">All CAs</option>
          {[...cas.values()]
            .filter((c) => c.kind === "intermediate")
            .map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
        </select>
        {params.get("tag") && (
          <button className="secondary small" onClick={() => setParam("tag", "")}>
            Tag: {params.get("tag")} ✕
          </button>
        )}
      </div>
      <ErrorBox error={error} />
      {!certs ? (
        <Loading />
      ) : certs.length === 0 ? (
        <p className="muted">No certificates match.</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Other names</th>
              <th>Issuer</th>
              <th>Expires</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {certs.map((c) => {
              const others = [...c.sans.dns, ...c.sans.ip].filter((n) => n !== c.commonName);
              return (
                <tr key={c.id}>
                  <td>
                    <Link to={`/certificates/${c.id}`}>{c.commonName}</Link>
                    {c.tags.length > 0 && (
                      <div>
                        {c.tags.map((t) => (
                          <button key={t} className="tag" onClick={() => setParam("tag", t)}>
                            {t}
                          </button>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="muted small">{others.slice(0, 3).join(", ") + (others.length > 3 ? ` +${others.length - 3}` : "")}</td>
                  <td className="small">{cas.get(c.caId)?.name ?? "—"}</td>
                  <td>{formatDate(c.notAfter)}</td>
                  <td>
                    <StatusBadge status={c.status} notAfter={c.notAfter} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
