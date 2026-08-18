import http from "node:http";

const socketPath = process.env.NETWORK_COLLECTOR_SOCKET ?? "/run/zimabrain-network/collector.sock";
const request = http.request({ socketPath, path: "/health", method: "GET", timeout: 3000 }, (response) => {
  process.exit(response.statusCode === 200 ? 0 : 1);
});
request.on("timeout", () => request.destroy(new Error("healthcheck timeout")));
request.on("error", () => process.exit(1));
request.end();
