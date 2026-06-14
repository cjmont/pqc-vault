// Downloads the official NIST ACVP-Server test vectors, filters them to the
// parameter sets and interfaces pqc-vault actually exposes (ML-KEM-768 and
// ML-DSA-65, external/pure signatures), and vendors a trimmed subset with a
// SHA-256 manifest. Run: node scripts/vendor-acvp.mjs
import { writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";

const RAW =
  "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files";
const OUT = new URL("../crates/pqc-vault-core/tests/vectors/", import.meta.url);
mkdirSync(OUT, { recursive: true });

async function fetchProjection(dir) {
  const res = await fetch(`${RAW}/${dir}/internalProjection.json`);
  if (!res.ok) throw new Error(`${dir}: HTTP ${res.status}`);
  return res.json();
}

// pick: (group) => bool ; map: (test, group) => trimmed test object
function extract(j, pick, map) {
  const out = [];
  for (const g of j.testGroups) {
    if (!pick(g)) continue;
    for (const t of g.tests) out.push(map(t, g));
  }
  return out;
}

const files = {};

// ---- ML-KEM-768 ----
{
  const kg = await fetchProjection("ML-KEM-keyGen-FIPS203");
  files["ml-kem-768-keygen.json"] = extract(
    kg,
    (g) => g.parameterSet === "ML-KEM-768",
    (t) => ({ tcId: t.tcId, d: t.d, z: t.z, ek: t.ek, dk: t.dk }),
  );

  const ed = await fetchProjection("ML-KEM-encapDecap-FIPS203");
  files["ml-kem-768-encap.json"] = extract(
    ed,
    (g) => g.parameterSet === "ML-KEM-768" && g.function === "encapsulation",
    (t) => ({ tcId: t.tcId, ek: t.ek, m: t.m, c: t.c, k: t.k }),
  );
  files["ml-kem-768-decap.json"] = extract(
    ed,
    (g) => g.parameterSet === "ML-KEM-768" && g.function === "decapsulation",
    (t) => ({ tcId: t.tcId, dk: t.dk, c: t.c, k: t.k }),
  );
}

// ---- ML-DSA-65 (external interface, pure) ----
{
  const kg = await fetchProjection("ML-DSA-keyGen-FIPS204");
  files["ml-dsa-65-keygen.json"] = extract(
    kg,
    (g) => g.parameterSet === "ML-DSA-65",
    (t) => ({ tcId: t.tcId, seed: t.seed, pk: t.pk, sk: t.sk }),
  );

  const sg = await fetchProjection("ML-DSA-sigGen-FIPS204");
  const pureExt = (g) =>
    g.parameterSet === "ML-DSA-65" &&
    g.signatureInterface === "external" &&
    g.preHash === "pure" &&
    g.externalMu === false;
  files["ml-dsa-65-siggen.json"] = extract(sg, pureExt, (t, g) => ({
    tcId: t.tcId,
    deterministic: g.deterministic,
    message: t.message,
    context: t.context ?? "",
    rnd: t.rnd ?? null,
    sk: t.sk,
    signature: t.signature,
  }));

  const sv = await fetchProjection("ML-DSA-sigVer-FIPS204");
  files["ml-dsa-65-sigver.json"] = extract(sv, pureExt, (t) => ({
    tcId: t.tcId,
    testPassed: t.testPassed,
    message: t.message,
    context: t.context ?? "",
    pk: t.pk,
    signature: t.signature,
  }));
}

const manifest = {
  source: "usnistgov/ACVP-Server gen-val/json-files (internalProjection.json)",
  branch: "master",
  note: "Trimmed to ML-KEM-768 and ML-DSA-65 (external/pure). Vendored by scripts/vendor-acvp.mjs.",
  files: {},
};

for (const [name, data] of Object.entries(files)) {
  const json = JSON.stringify(data, null, 0);
  writeFileSync(new URL(name, OUT), json);
  manifest.files[name] = {
    count: data.length,
    sha256: createHash("sha256").update(json).digest("hex"),
  };
  console.log(`${name}: ${data.length} cases`);
}

writeFileSync(
  new URL("manifest.json", OUT),
  JSON.stringify(manifest, null, 2),
);
console.log("manifest.json written");
