// functions/_shared/oidc.js
// Validação do id_token do Google sem bibliotecas externas.

import { base64UrlDecodeToBytes } from "./crypto.js";

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error("discovery_fetch_failed");
  return res.json();
}

export async function validateGoogleIdToken(idToken, { clientId, expectedNonce }) {
  if (!idToken || typeof idToken !== "string") throw new Error("missing_id_token");

  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("invalid_jwt_format");
  const [headerB64, payloadB64, signatureB64] = parts;

  const header = JSON.parse(new TextDecoder().decode(base64UrlDecodeToBytes(headerB64)));
  const payload = JSON.parse(new TextDecoder().decode(base64UrlDecodeToBytes(payloadB64)));

  if (header.alg !== "RS256") throw new Error("unexpected_alg");

  // 1. documento de descoberta OIDC do emissor esperado
  const discovery = await fetchJson("https://accounts.google.com/.well-known/openid-configuration");

  // 2. conjunto de chaves JWKS
  const jwks = await fetchJson(discovery.jwks_uri);

  // 3. seleciona a chave pública pelo kid do cabeçalho
  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("key_not_found");

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlDecodeToBytes(signatureB64);

  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, signedData);
  if (!valid) throw new Error("bad_signature");

  const now = Math.floor(Date.now() / 1000);

  if (payload.iss !== discovery.issuer && payload.iss !== "https://accounts.google.com") {
    throw new Error("bad_issuer");
  }
  if (payload.aud !== clientId) throw new Error("bad_audience");
  if (typeof payload.exp !== "number" || payload.exp < now) throw new Error("expired");
  if (typeof payload.iat !== "number" || payload.iat > now + 60) throw new Error("bad_iat");
  if (expectedNonce && payload.nonce !== expectedNonce) throw new Error("bad_nonce");

  return payload; // contém sub, email, name, etc.
}
