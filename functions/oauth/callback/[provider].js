import { parseCookies, setCookie, expireCookie } from "../../_shared/cookies.js";
import { randomToken, sha256Base64Url } from "../../_shared/crypto.js";
import { PROVIDERS, getRedirectUri, getClientId, getClientSecret } from "../../_shared/providers.js";
import { validateGoogleIdToken } from "../../_shared/oidc.js";

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const provider = params.provider;

  if (provider !== "google" && provider !== "github") {
    return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
  }

  const url = new URL(request.url);
  const errorParam = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (errorParam || !code || !state) return badRequest();

  const cookies = parseCookies(request);
  const txValue = cookies["__Host-oauth-tx"];
  if (!txValue) return badRequest();

  const txHash = await sha256Base64Url(txValue);
  const now = Math.floor(Date.now() / 1000);

  const tx = await env.DB.prepare(
    `SELECT provider, state_hash, nonce, code_verifier, expires_at
     FROM oauth_transactions WHERE id_hash = ?`
  )
    .bind(txHash)
    .first();

  if (!tx || tx.provider !== provider || tx.expires_at < now) return badRequest();

  const stateHash = await sha256Base64Url(state);
  if (stateHash !== tx.state_hash) {
    await env.DB.prepare("DELETE FROM oauth_transactions WHERE id_hash = ?").bind(txHash).run();
    return badRequest();
  }

  // A transação é de uso único: apaga antes de concluir o fluxo.
  await env.DB.prepare("DELETE FROM oauth_transactions WHERE id_hash = ?").bind(txHash).run();

  const config = PROVIDERS[provider];
  const redirectUri = getRedirectUri(env, provider);
  const clientId = getClientId(env, provider);
  const clientSecret = getClientSecret(env, provider);

  let identity;

  try {
    if (provider === "google") {
      const tokenRes = await fetch(config.tokenEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          grant_type: "authorization_code",
          code_verifier: tx.code_verifier,
        }),
      });
      if (!tokenRes.ok) throw new Error("token_exchange_failed");
      const tokenBody = await tokenRes.json();

      const payload = await validateGoogleIdToken(tokenBody.id_token, {
        clientId,
        expectedNonce: tx.nonce,
      });

      identity = {
        issuer: "https://accounts.google.com",
        subject: payload.sub,
        email: payload.email || null,
        displayName: payload.name || payload.email || null,
      };
    } else {
      const tokenRes = await fetch(config.tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          code_verifier: tx.code_verifier,
        }),
      });
      if (!tokenRes.ok) throw new Error("token_exchange_failed");
      const tokenBody = await tokenRes.json();

      if (!tokenBody.access_token || !/^bearer$/i.test(tokenBody.token_type || "")) {
        throw new Error("bad_token_response");
      }

      const userRes = await fetch(config.userEndpoint, {
        headers: {
          Authorization: `Bearer ${tokenBody.access_token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
          "User-Agent": "oauth-pages-lab",
        },
      });
      if (!userRes.ok) throw new Error("user_fetch_failed");
      const userBody = await userRes.json();
      if (typeof userBody.id !== "number") throw new Error("bad_user_response");

      // Revoga a autorização concedida à OAuth App antes de criar a sessão local.
      const revokeRes = await fetch(`https://api.github.com/applications/${clientId}/grant`, {
        method: "DELETE",
        headers: {
          Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
          "Content-Type": "application/json",
          "User-Agent": "oauth-pages-lab",
        },
        body: JSON.stringify({ access_token: tokenBody.access_token }),
      });
      if (revokeRes.status !== 204) throw new Error("revoke_failed");

      identity = {
        issuer: "https://github.com",
        subject: String(userBody.id),
        email: userBody.email || null,
        displayName: userBody.name || userBody.login || null,
      };
    }
  } catch (e) {
    return badRequest();
  }

  const sessionValue = randomToken(32);
  const sessionHash = await sha256Base64Url(sessionValue);
  const sessionExpiresAt = now + 8 * 60 * 60; // 8 horas

  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(sessionHash, identity.issuer, identity.subject, identity.email, identity.displayName, sessionExpiresAt, now)
    .run();

  const headers = new Headers();
  headers.set("Location", env.PUBLIC_BASE_URL);
  headers.append("Set-Cookie", expireCookie("__Host-oauth-tx", { sameSite: "Lax" }));
  headers.append("Set-Cookie", setCookie("__Host-session", sessionValue, { maxAge: 28800, sameSite: "Strict" }));
  headers.set("Cache-Control", "no-store");

  return new Response(null, { status: 302, headers });
}

function badRequest() {
  return new Response("Bad request", { status: 400, headers: { "Cache-Control": "no-store" } });
}
