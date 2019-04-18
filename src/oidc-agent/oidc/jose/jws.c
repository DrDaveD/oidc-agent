#include "jws.h"
#include "jwk.h"

oidc_error_t verifyIdToken(const struct oidc_account* account) {
  char* iss_jwk = getIssuerJWK(account);
  return OIDC_NOTIMPL;
}
