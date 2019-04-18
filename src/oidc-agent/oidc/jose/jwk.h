#ifndef OIDCAGENT_JWK_H
#define OIDCAGENT_JWK_H

#include "account/account.h"

char* getIssuerJWKFromUrl(const char* jwks_url);
char* getIssuerJWK(const struct oidc_account* p);

#endif  // OIDCAGENT_JWK_H
