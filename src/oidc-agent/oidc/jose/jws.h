#ifndef OIDCAGENT_JWS_H
#define OIDCAGENT_JWS_H

#include "account/account.h"
#include "utils/oidc_error.h"

oidc_error_t verifyIdToken(const struct oidc_account*);

#endif  // OIDCAGENT_JWS_H
