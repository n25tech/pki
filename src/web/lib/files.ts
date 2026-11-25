/** Saves text as a file download. */
export function download(filename: string, content: string, type = "application/x-pem-file") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function readFileText(file: File): Promise<string> {
  return file.text();
}

/** A filesystem-friendly version of a name, e.g. "nas.home.arpa" → "nas.home.arpa", "My Root" → "my-root". */
export function slug(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "") || "certificate";
}

export function formatDate(ms: number | null | undefined): string {
  if (!ms) return "—";
  return new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function formatDateTime(ms: number | null | undefined): string {
  if (!ms) return "—";
  return new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function daysUntil(ms: number): number {
  return Math.round((ms - Date.now()) / 86_400_000);
}

export function lines(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Kubernetes TLS secret manifest. */
export function kubernetesSecret(name: string, certChainPem: string, keyPem: string): string {
  const b64 = (s: string) => btoa(s);
  return `apiVersion: v1
kind: Secret
metadata:
  name: ${slug(name).replace(/\./g, "-")}-tls
type: kubernetes.io/tls
data:
  tls.crt: ${b64(certChainPem)}
  tls.key: ${b64(keyPem)}
`;
}
