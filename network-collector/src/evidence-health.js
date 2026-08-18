const checks = [
  ["/sensors", (payload) => payload?.verified === true],
  ["/failed-services", (payload) => payload?.verified === true],
  ["/journal-errors", (payload) => payload?.verified === true],
  ["/rauc", (payload) => payload?.verified === true && payload?.updateStateVerified === true],
];

export function systemEvidenceSummary(payloads) {
  const results = Object.fromEntries(checks.map(([path, predicate]) => [
    path,
    payloads.get(path)?.collectorStatus === "success" && predicate(payloads.get(path)),
  ]));
  return {
    allVerified: Object.values(results).every(Boolean),
    results,
  };
}
