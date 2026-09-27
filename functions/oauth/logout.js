import { parseCookies, expireCookie } from "../_shared/cookies.js";
import { sha256Base64Url } from "../_shared/crypto.js";

export async function onRequestPost(context) {
  const { request, env } = context;

  const origin = request.headers.get("Origin");
  if (origin !== env.PUBLIC_BASE_URL) {
    return new Response("Forbidden", { status: 403, headers: { "Cache-Control": "no-store" } });
  }

  const cookies = parseCookies(request);
  const raw = cookies["__Host-session"];

  if (raw) {
    const idHash = await sha256Base64Url(raw);
    await env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(idHash).run();
  }

  const headers = new Headers();
  headers.append("Set-Cookie", expireCookie("__Host-session", { sameSite: "Strict" }));
  headers.set("Cache-Control", "no-store");
  // Redireciona de volta para a base pública após o logout via formulário.
  headers.set("Location", env.PUBLIC_BASE_URL);

  return new Response(null, { status: 302, headers });
}

export async function onRequestGet() {
  return new Response("Method not allowed", { status: 405, headers: { "Cache-Control": "no-store" } });
}
