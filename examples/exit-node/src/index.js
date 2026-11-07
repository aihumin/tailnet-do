import { TailnetObject } from "../../../src/index.js";

// One Durable Object = one tailnet device. It serves a small page to tailnet
// peers on port 80, and can optionally act as an exit node (TS_EXIT_NODE=1).
export class ExitNode extends TailnetObject {
  tailnetOptions() {
    return {
      ...super.tailnetOptions(),
      hostname: this.env.TS_HOSTNAME ?? "cf-exit",
      exitNode: this.env.TS_EXIT_NODE === "1",
      statePrefix: "ts:", // keeps the device identity from the first prototype
    };
  }

  async onTailnet(tailnet) {
    tailnet.serve(80, (request, who) =>
      Response.json({
        hello: who?.displayName ?? "unknown",
        you: who,
        node: tailnet.status().name,
        path: new URL(request.url).pathname,
      }),
    );
  }

  async fetch(request) {
    return Response.json({ ...(await this.tailnetStatus()), colo: request.cf?.colo });
  }
}

export default {
  async fetch(request, env) {
    // Everything here (status, login URL, tailnet proxy) is private. Require
    // ACCESS_TOKEN as a bearer token or ?token=. Only localhost may skip it.
    const url = new URL(request.url);
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (env.ACCESS_TOKEN || !local) {
      const given =
        request.headers.get("authorization")?.replace(/^Bearer /, "") ?? url.searchParams.get("token");
      if (!env.ACCESS_TOKEN || given !== env.ACCESS_TOKEN) {
        return new Response("unauthorized", { status: 401 });
      }
    }
    const node = env.EXIT.getByName("exit");
    // /tailnet?url=http://host:port/path fetches a tailnet URL via the DO.
    if (url.pathname === "/tailnet") {
      return node.tailnetFetch(url.searchParams.get("url"));
    }
    return node.fetch(request);
  },
};
