import { parseCookies } from "../_shared/cookies.js";
import { sha256Base64Url } from "../_shared/crypto.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const cookies = parseCookies(request);
  const raw = cookies["__Host-session"];

  if (!raw) return unauthorized();

  const idHash = await sha256Base64Url(raw);
  const now = Math.floor(Date.now() / 1000);

  const row = await env.DB.prepare(
    `SELECT issuer, subject, email, display_name, expires_at
     FROM sessions WHERE id_hash = ?`
  )
    .bind(idHash)
    .first();

  if (!row || row.expires_at < now) return unauthorized();

  return Response.json(
    {
      issuer: row.issuer,
      subject: row.subject,
      email: row.email,
      displayName: row.display_name,
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}

function unauthorized() {
  return Response.json(
    { error: "unauthorized" },
    { status: 401, headers: { "Cache-Control": "no-store" } }
  );
}
