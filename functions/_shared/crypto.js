// functions/_shared/crypto.js
// Helpers de aleatoriedade e resumo criptográfico usando apenas Web Crypto.

export function base64UrlEncode(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function base64UrlDecodeToBytes(str) {
  const padLength = (4 - (str.length % 4)) % 4;
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padLength);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Gera 32 bytes aleatórios codificados em Base64URL sem preenchimento (43 caracteres).
export function randomToken(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function sha256Base64Url(input) {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(digest));
}

// PKCE: o code_challenge é o SHA-256 do code_verifier, em Base64URL (método S256).
export async function codeChallengeFromVerifier(verifier) {
  return sha256Base64Url(verifier);
}
