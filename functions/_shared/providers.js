// functions/_shared/providers.js

export const PROVIDERS = {
  google: {
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    discoveryUrl: "https://accounts.google.com/.well-known/openid-configuration",
    scope: "openid email profile",
  },
  github: {
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    userEndpoint: "https://api.github.com/user",
  },
};

export function getRedirectUri(env, provider) {
  return `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
}

export function getClientId(env, provider) {
  return provider === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;
}

export function getClientSecret(env, provider) {
  return provider === "google" ? env.GOOGLE_CLIENT_SECRET : env.GITHUB_CLIENT_SECRET;
}
