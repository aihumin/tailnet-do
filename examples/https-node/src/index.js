import { TailnetObject } from "../../../src/index.js";

// One Durable Object = one tailnet device that answers on
// https://<hostname>.<tailnet>.ts.net/ with a certificate Tailscale issues
// through Let's Encrypt. The tailnet needs HTTPS Certificates enabled (admin
// console, DNS page).
//
// Vars: TS_AUTHKEY, TS_HOSTNAME (default "https-node"), and
// TS_ACME_DIRECTORY_URL to use another ACME directory, such as Let's
// Encrypt staging while you experiment.
export class HttpsNode extends TailnetObject {
  tailnetOptions() {
    return { ...super.tailnetOptions(), hostname: this.env.TS_HOSTNAME ?? "https-node" };
  }

  async onTailnet(tailnet) {
    const hello = (request, who) => new Response(`hello ${who?.loginName ?? "stranger"}\n`);

    const https = tailnet.serveHTTPS(443, hello);
    https.ready.then(
      (cert) => console.log(`serving https://${cert.domain}/, certificate expires ${cert.expiry}`),
      (err) => console.log(`HTTPS is not ready: ${err.message}`),
    );

    // Plain HTTP keeps working next to it.
    tailnet.serve(80, hello);
  }

  async fetch(request) {
    const tailnet = await this.tailnet();
    // POST /renew replaces the certificate now, to try the renewal path.
    if (request.method === "POST" && new URL(request.url).pathname === "/renew") {
      return Response.json(await tailnet.renewCertificate());
    }
    return Response.json(tailnet.status());
  }
}

export default {
  async fetch(request, env) {
    // The node's status (and login URL) is private. Require ACCESS_TOKEN as a
    // bearer token or ?token=. Only localhost may skip it.
    const url = new URL(request.url);
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (env.ACCESS_TOKEN || !local) {
      const given =
        request.headers.get("authorization")?.replace(/^Bearer /, "") ?? url.searchParams.get("token");
      if (!env.ACCESS_TOKEN || given !== env.ACCESS_TOKEN) {
        return new Response("unauthorized", { status: 401 });
      }
    }
    return env.NODE.getByName("main").fetch(request);
  },
};
