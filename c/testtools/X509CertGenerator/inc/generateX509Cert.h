#ifndef GENERATE_X509_CERT_H
#define GENERATE_X509_CERT_H

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif // __cplusplus

typedef void* X509CertHandle;

X509CertHandle createX509Auth();
char* getCert(X509CertHandle handle);
unsigned char* getThumbPrint(X509CertHandle handle);
char* getRSAKey(X509CertHandle handle);
void destroyX509Auth(X509CertHandle handle);

#ifdef __cplusplus
}
#endif
#endif // !GENERATE_X509_CERT_H