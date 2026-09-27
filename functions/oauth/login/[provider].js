import { randomToken, sha256Base64Url, codeChallengeFromVerifier } from "../../_shared/crypto.js";
import { setCookie } from "../../_shared/cookies.js";
import { PROVIDERS, getRedirectUri, getClientId } from "../../_shared/providers.js";

export async function onRequestGet(context) {
  const { params, env } = context;
  const provider = params.provider;

  if (provider !== "google" && provider !== "github") {
    return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
  }

  const config = PROVIDERS[provider];

  // Identificador bruto da transação (fica só no cookie; o D1 guarda o resumo)
  const txValue = randomToken(32);
  const txHash = await sha256Base64Url(txValue);

  const state = randomToken(32);
  const stateHash = await sha256Base64Url(state);

  const codeVerifier = randomToken(32);
  const codeChallenge = await codeChallengeFromVerifier(codeVerifier);

  const nonce = provider === "google" ? randomToken(32) : null;

  const expiresAt = Math.floor(Date.now() / 1000) + 600; // 10 minutos

  await env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(txHash, provider, stateHash, nonce, codeVerifier, expiresAt)
    .run();

  const redirectUri = getRedirectUri(env, provider);
  const clientId = getClientId(env, provider);

  const authUrl = new URL(config.authorizationEndpoint);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  if (provider === "google") {
    authUrl.searchParams.set("scope", config.scope);
    authUrl.searchParams.set("nonce", nonce);
  }
  // No GitHub: scope e nonce ficam de fora de propósito.

  const headers = new Headers();
  headers.set("Location", authUrl.toString());
  headers.append("Set-Cookie", setCookie("__Host-oauth-tx", txValue, { maxAge: 600, sameSite: "Lax" }));
  headers.set("Cache-Control", "no-store");

  return new Response(null, { status: 302, headers });
}
