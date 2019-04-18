#include "jwk.h"
#include "utils/oidc_error.h"

char* getIssuerJWKFromUrl(const char* jwks_url) {
  oidc_errno = OIDC_NOTIMPL;
  return NULL;
}

char* getIssuerJWK(const struct oidc_account* account) {
  if (account == NULL) {
    oidc_setArgNullFuncError(__func__);
    return NULL;
  }
  return getIssuerJWKFromUrl(account_getJwksUrl(account));
}
