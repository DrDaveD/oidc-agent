#include "setandget.h"

struct oidc_issuer* account_getIssuer(const struct oidc_account* p) {
  return p ? p->issuer : NULL;
}

char* account_getIssuerUrl(const struct oidc_account* p) {
  return p ? p->issuer ? issuer_getIssuerUrl(p->issuer) : NULL : NULL;
}

char* account_getConfigEndpoint(const struct oidc_account* p) {
  return p ? p->issuer ? issuer_getConfigEndpoint(p->issuer) : NULL : NULL;
}

char* account_getTokenEndpoint(const struct oidc_account* p) {
  return p ? p->issuer ? issuer_getTokenEndpoint(p->issuer) : NULL : NULL;
}

char* account_getAuthorizationEndpoint(const struct oidc_account* p) {
  return p ? p->issuer ? issuer_getAuthorizationEndpoint(p->issuer) : NULL
           : NULL;
}

char* account_getRevocationEndpoint(const struct oidc_account* p) {
  return p ? p->issuer ? issuer_getRevocationEndpoint(p->issuer) : NULL : NULL;
}

char* account_getRegistrationEndpoint(const struct oidc_account* p) {
  return p ? p->issuer ? issuer_getRegistrationEndpoint(p->issuer) : NULL
           : NULL;
}

char* account_getDeviceAuthorizationEndpoint(const struct oidc_account* p) {
  return p ? p->issuer ? issuer_getDeviceAuthorizationEndpoint(p->issuer) : NULL
           : NULL;
}

char* account_getScopesSupported(const struct oidc_account* p) {
  return p ? p->issuer ? issuer_getScopesSupported(p->issuer) : NULL : NULL;
}

char* account_getGrantTypesSupported(const struct oidc_account* p) {
  return p ? p->issuer ? issuer_getGrantTypesSupported(p->issuer) : NULL : NULL;
}

char* account_getResponseTypesSupported(const struct oidc_account* p) {
  return p ? p->issuer ? issuer_getResponseTypesSupported(p->issuer) : NULL
           : NULL;
}

char* account_getName(const struct oidc_account* p) {
  return p ? p->shortname : NULL;
}

char* account_getClientName(const struct oidc_account* p) {
  return p ? p->client_data.clientname : NULL;
}

char* account_getClientId(const struct oidc_account* p) {
  return p ? p->client_data.client_credentials.client_id : NULL;
}

char* account_getClientSecret(const struct oidc_account* p) {
  return p ? p->client_data.client_credentials.client_secret : NULL;
}

char* account_getScope(const struct oidc_account* p) {
  return p ? p->client_data.scope : NULL;
}

char* account_getUsername(const struct oidc_account* p) {
  return p ? p->account_credentials.username : NULL;
}

char* account_getPassword(const struct oidc_account* p) {
  return p ? p->account_credentials.password : NULL;
}

char* account_getRefreshToken(const struct oidc_account* p) {
  return p ? p->tokens.refresh_token : NULL;
}

char* account_getAccessToken(const struct oidc_account* p) {
  return p ? p->tokens.at.access_token : NULL;
}

char* account_getIdToken(const struct oidc_account* p) {
  return p ? p->tokens.id_token : NULL;
}

unsigned long account_getTokenExpiresAt(const struct oidc_account* p) {
  return p ? p->tokens.at.token_expires_at : 0;
}

char* account_getCertPath(const struct oidc_account* p) {
  return p ? p->cert_path : NULL;
}

list_t* account_getRedirectUris(const struct oidc_account* p) {
  return p ? p->client_data.redirect_uris : NULL;
}

size_t account_getRedirectUrisCount(const struct oidc_account* p) {
  return p ? p->client_data.redirect_uris ? p->client_data.redirect_uris->len
                                          : 0
           : 0;
}

char* account_getUsedState(const struct oidc_account* p) {
  return p ? p->internal.usedState : NULL;
}

time_t account_getDeath(const struct oidc_account* p) {
  return p ? p->internal.death : 0;
}

char* account_getCodeChallengeMethod(const struct oidc_account* p) {
  return p ? p->internal.code_challenge_method : NULL;
}

unsigned char account_getConfirmationRequired(const struct oidc_account* p) {
  return p ? p->internal.mode & ACCOUNT_MODE_CONFIRM : 0;
}

unsigned char account_getNoWebServer(const struct oidc_account* p) {
  return p ? p->internal.mode & ACCOUNT_MODE_NO_WEBSERVER : 0;
}

void account_setIssuerUrl(struct oidc_account* p, char* issuer_url) {
  if (!p->issuer) {
    p->issuer = secAlloc(sizeof(struct oidc_issuer));
  }
  issuer_setIssuerUrl(p->issuer, issuer_url);
}

void account_setClientName(struct oidc_account* p, char* clientname) {
  if (p->client_data.clientname == clientname) {
    return;
  }
  secFree(p->client_data.clientname);
  p->client_data.clientname = clientname;
}

void account_setName(struct oidc_account* p, char* shortname,
                     const char* client_identifier) {
  if (p->shortname == shortname) {
    return;
  }
  secFree(p->shortname);
  p->shortname = shortname;
  char* clientname =
      strValid(client_identifier)
          ? oidc_sprintf("oidc-agent:%s-%s", shortname, client_identifier)
          : strValid(shortname) ? oidc_strcat("oidc-agent:", shortname) : NULL;
  account_setClientName(p, clientname);
}

void account_setClientId(struct oidc_account* p, char* client_id) {
  if (p->client_data.client_credentials.client_id == client_id) {
    return;
  }
  secFree(p->client_data.client_credentials.client_id);
  p->client_data.client_credentials.client_id = client_id;
}

void account_setClientSecret(struct oidc_account* p, char* client_secret) {
  if (p->client_data.client_credentials.client_secret == client_secret) {
    return;
  }
  secFree(p->client_data.client_credentials.client_secret);
  p->client_data.client_credentials.client_secret = client_secret;
}

void account_setScopeExact(struct oidc_account* p, char* scope) {
  if (p->client_data.scope == scope) {
    return;
  }
  secFree(p->client_data.scope);
  p->client_data.scope = scope;
}

void account_setScope(struct oidc_account* p, char* scope) {
  account_setScopeExact(p, scope);
  if (strValid(scope)) {
    char* usable = defineUsableScopes(p);
    account_setScopeExact(p, usable);
  }
}

void account_setIssuer(struct oidc_account* p, struct oidc_issuer* issuer) {
  if (p->issuer == issuer) {
    return;
  }
  secFreeIssuer(p->issuer);
  p->issuer = issuer;
  if (issuer && strValid(account_getScope(p))) {
    account_setScopeExact(p, defineUsableScopes(p));
  }
}

void account_setScopesSupported(struct oidc_account* p,
                                char*                scopes_supported) {
  if (!p->issuer) {
    p->issuer = secAlloc(sizeof(struct oidc_issuer));
  }
  if (p->issuer->scopes_supported == scopes_supported) {
    return;
  }
  issuer_setScopesSupported(p->issuer, scopes_supported);
  char* usable = defineUsableScopes(p);
  account_setScopeExact(p, usable);
}

void account_setUsername(struct oidc_account* p, char* username) {
  if (p->account_credentials.username == username) {
    return;
  }
  secFree(p->account_credentials.username);
  p->account_credentials.username = username;
}

void account_setPassword(struct oidc_account* p, char* password) {
  if (p->account_credentials.password == password) {
    return;
  }
  secFree(p->account_credentials.password);
  p->account_credentials.password = password;
}

void account_setRefreshToken(struct oidc_account* p, char* refresh_token) {
  if (p->tokens.refresh_token == refresh_token) {
    return;
  }
  secFree(p->tokens.refresh_token);
  p->tokens.refresh_token = refresh_token;
}

void account_setAccessToken(struct oidc_account* p, char* access_token) {
  if (p->tokens.at.access_token == access_token) {
    return;
  }
  secFree(p->tokens.at.access_token);
  p->tokens.at.access_token = access_token;
}

void account_setIdToken(struct oidc_account* p, char* id_token) {
  if (p->tokens.id_token == id_token) {
    return;
  }
  secFree(p->tokens.id_token);
  p->tokens.id_token = id_token;
}

void account_setTokenExpiresAt(struct oidc_account* p,
                               unsigned long        token_expires_at) {
  if (p->tokens.at.token_expires_at == token_expires_at) {
    return;
  }
  p->tokens.at.token_expires_at = token_expires_at;
}

void account_setCertPath(struct oidc_account* p, char* cert_path) {
  if (p->cert_path == cert_path) {
    return;
  }
  secFree(p->cert_path);
  p->cert_path = cert_path;
}

void account_setRedirectUris(struct oidc_account* p, list_t* redirect_uris) {
  if (p->client_data.redirect_uris == redirect_uris) {
    return;
  }
  if (p->client_data.redirect_uris) {
    list_destroy(p->client_data.redirect_uris);
  }
  p->client_data.redirect_uris = redirect_uris;
}

void account_setUsedState(struct oidc_account* p, char* used_state) {
  if (p->internal.usedState == used_state) {
    return;
  }
  secFree(p->internal.usedState);
  p->internal.usedState = used_state;
}

void account_clearCredentials(struct oidc_account* a) {
  account_setUsername(a, NULL);
  account_setPassword(a, NULL);
}

void account_setDeath(struct oidc_account* p, time_t death) {
  p->internal.death = death;
}

void account_setCodeChallengeMethod(struct oidc_account* p,
                                    char* code_challenge_method) {
  if (p->internal.code_challenge_method == code_challenge_method) {
    return;
  }
  secFree(p->internal.code_challenge_method);
  p->internal.code_challenge_method = code_challenge_method;
}

void account_setConfirmationRequired(struct oidc_account* p) {
  p->internal.mode |= ACCOUNT_MODE_CONFIRM;
}

void account_setNoWebServer(struct oidc_account* p) {
  p->internal.mode |= ACCOUNT_MODE_NO_WEBSERVER;
}

int account_refreshTokenIsValid(const struct oidc_account* p) {
  char* refresh_token = account_getRefreshToken(p);
  int   ret           = strValid(refresh_token);
  return ret;
}
