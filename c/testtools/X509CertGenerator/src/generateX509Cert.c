#include "generateX509Cert.h"
#include "azure_c_shared_utility/xlogging.h"
#include <openssl\bio.h>
#include "openSSl\x509.h"
#include "openssl\pem.h"
#include <stdio.h>
#include <direct.h>

typedef enum X509_GENERATE_CERT_STATUS
{
    X509_GENERATE_KEY_FAILED,
    X509_GENERATE_KEY_OK,
    X509_GENERATE_CERT_FAILED,
    X509_GENERATE_CERT_OK
} X509_GENERATE_CERT_STATUS;

const char* keyFileName = "rsa_key.pem";
const char* certFileName = "cert.pem";

typedef struct KEY {
        EVP_PKEY* pkey;
        RSA* rsaKey;
        char* fKeyPath;
}KEY;

typedef struct CERTIFICATE {
        char* fCertPath;
        X509* x509;
        unsigned char* thumbPrint;
}CERTIFICATE;

typedef struct X509Auth {
    KEY* key;
    CERTIFICATE* cert;
}X509Auth;

typedef void* X509CertHandle;

static X509_GENERATE_CERT_STATUS createKey(X509CertHandle handle) {
    X509_GENERATE_CERT_STATUS ret;
    if (handle != NULL) {
        X509Auth* auth = (X509Auth*)handle;
        if (auth->key != NULL) {
            auth->key->pkey = EVP_PKEY_new();
            if (auth->key->pkey != NULL) {
                auth->key->rsaKey = RSA_new();
                if (auth->key->rsaKey != NULL) {
                    BIGNUM* e = BN_new();
                    BN_set_word(e, RSA_F4);
                    if ((RSA_generate_key_ex(auth->key->rsaKey, 2048, e, NULL)) == 1) {
                        BN_free(e);
                        EVP_PKEY_assign_RSA(auth->key->pkey, auth->key->rsaKey);
                        char* buf = _getcwd(NULL, 0);
                        auth->key->fKeyPath = (char*)malloc(strlen(buf) + strlen(keyFileName) + 2);
                        strncpy(auth->key->fKeyPath, buf, strlen(buf));
                        strncpy(auth->key->fKeyPath + strlen(buf), "\\", 2);
                        strncpy(auth->key->fKeyPath + strlen(buf) + 1, keyFileName, strlen(keyFileName));
                        strncpy(auth->key->fKeyPath + strlen(buf) + strlen(keyFileName) + 1, "\0", 1);
                        free((void*)buf);
                        BIO* bKey = BIO_new_file(auth->key->fKeyPath, "w+");
                        if ((bKey != NULL) && (PEM_write_bio_RSAPrivateKey(bKey, auth->key->rsaKey, NULL, NULL, 0, 0, NULL) == 1)) {
                            BIO_free(bKey);
                            ret = X509_GENERATE_KEY_OK;
                        }
                        else {
                            LogError("failed to write key to the file");
                            EVP_PKEY_free(auth->key->pkey);
                            auth->key->pkey = NULL;
                            ret = X509_GENERATE_KEY_FAILED;
                        }
                    }
                    else {
                        LogError("failed to generate RSA key");
                        EVP_PKEY_free(auth->key->pkey);
                        auth->key->pkey = NULL;
                        BN_free(e);
                        ret = X509_GENERATE_KEY_FAILED;
                    }
                }
                else {
                    LogError("failed to create RSA key");
                    ret = X509_GENERATE_KEY_FAILED;
                }
            }
            else {
                    LogError("failed to create private key");
                    ret = X509_GENERATE_KEY_FAILED;
                }
        }
        else {
            LogError("Key cannot be null");
            ret = X509_GENERATE_KEY_FAILED;
        }
    }
    else {
        LogError("handle cannot be null");
        ret = X509_GENERATE_KEY_FAILED;
    }

    return ret;
}

static X509_GENERATE_CERT_STATUS createCertificate(X509CertHandle handle) {
    X509_GENERATE_CERT_STATUS ret;
    if (handle != NULL) {
        X509Auth* auth = (X509Auth*) handle;
        if (auth->key != NULL && auth->key->pkey != NULL && auth->cert != NULL) {
            auth->cert->x509 = X509_new();
            if (auth->cert->x509 != NULL) {
                /*Set serial number*/
                int xret = ASN1_INTEGER_set(X509_get_serialNumber(auth->cert->x509), 1);
                /*Set validity for 365 days */
                X509_gmtime_adj(X509_get_notBefore(auth->cert->x509), 0);
                X509_gmtime_adj(X509_get_notAfter(auth->cert->x509), 31536000L);
                /*Set public key obtained earlier */
                xret = X509_set_pubkey(auth->cert->x509, auth->key->pkey);
                /*Set details for self signed certificate */
                X509_NAME *name = X509_get_subject_name(auth->cert->x509);

                xret = X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                    (unsigned char *)"US", -1, -1, 0);
                xret = X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                    (unsigned char *)"Microsoft Inc.", -1, -1, 0);
                xret = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                    (unsigned char *)"localhost", -1, -1, 0);
                xret = X509_set_issuer_name(auth->cert->x509, name);
                /*Sign the certificate*/
                xret = X509_sign(auth->cert->x509, auth->key->pkey, EVP_sha1());
                if (X509_verify(auth->cert->x509, auth->key->pkey) == 1) {
                    /*Write certificate to file */
                    char* buf = _getcwd(NULL, 0);
                    auth->cert->fCertPath = malloc(strlen(buf) + strlen(certFileName) + 2);
                    strncpy(auth->cert->fCertPath, buf, strlen(buf));
                    strncpy(auth->cert->fCertPath + strlen(buf), "\\", 2);
                    strncpy(auth->cert->fCertPath + strlen(buf) + 1, certFileName, strlen(certFileName));
                    strncpy(auth->cert->fCertPath + strlen(buf) + strlen(certFileName) + 1, "\0", 1);
                    free((void*)buf);
                    BIO* bCert = BIO_new_file(auth->cert->fCertPath, "w+");
                    if ((bCert != NULL) && (PEM_write_bio_X509(bCert, auth->cert->x509) == 1)) {
                        BIO_free(bCert);
                        unsigned char *thumbPrint = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
                        if (thumbPrint != NULL) {
                            unsigned int length;
                            if (X509_digest(auth->cert->x509, EVP_sha1(), thumbPrint, &length) == 1) {
                                auth->cert->thumbPrint = (unsigned char*)malloc(length + 1);
                                strncpy((char*)auth->cert->thumbPrint, (char*)thumbPrint, length);
                                free((void*)thumbPrint);
                                auth->cert->thumbPrint[length] = '\0';
                                ret = X509_GENERATE_CERT_OK;
                            }
                            else {
                                LogError("malloc to create thumbprint failed");
                                X509_free(auth->cert->x509);
                                auth->cert->x509 = NULL;
                                ret = X509_GENERATE_CERT_FAILED;
                            }
                        }
                        else {
                            LogError("Failed to malloc thumbprint");
                            X509_free(auth->cert->x509);
                            auth->cert->x509 = NULL;
                            ret = X509_GENERATE_CERT_FAILED;
                        }
                    }
                    else {
                        LogError("Failed to write certificate to the file");
                        X509_free(auth->cert->x509);
                        auth->cert->x509 = NULL;
                        ret = X509_GENERATE_CERT_FAILED;
                    }
                }
                else {
                    LogError("Signing unsuccessfull");
                    ret = X509_GENERATE_CERT_FAILED;
                }
            }
            else {
                LogError("Failed to create new x509");
                ret = X509_GENERATE_CERT_FAILED;
            }
        }
        else {
            LogError("Key cannot be null");
            ret = X509_GENERATE_CERT_FAILED;
        }
    }
    else {
        LogError("handle cannot be null");
        ret = X509_GENERATE_CERT_FAILED;
    }

    return ret;
}

X509CertHandle createX509Auth() {
    X509Auth* auth = (X509Auth*) malloc(sizeof(X509Auth));

    if (auth == NULL) {
        LogError("Failure to allocate memory for Authentication.");
        return NULL;
    }

    auth->key = (KEY*) malloc(sizeof(KEY));

    if (auth->key == NULL) {
        LogError("Failure to allocate memory for key.");
        free((void*) auth);
        auth = NULL;
        return NULL;
    }
    else {
        auth->key->pkey = NULL;
        auth->key->rsaKey = NULL;
        auth->key->fKeyPath = NULL;
    }

    auth->cert = (CERTIFICATE*) malloc(sizeof(CERTIFICATE));

    if (auth->cert == NULL) {
        LogError("Failure to allocate memory for key.");
        free((void*) auth->key);
        auth->key = NULL;
        free((void*) auth);
        auth = NULL;
        return NULL;
    }
    else {
        auth->cert->fCertPath = NULL;
        auth->cert->x509 = NULL;
        auth->cert->thumbPrint = NULL;
    }

    OpenSSL_add_all_algorithms();

    if ((createKey(auth) == X509_GENERATE_KEY_OK) && (createCertificate(auth) == X509_GENERATE_CERT_OK)) {
        return auth;
    }
    else {
        LogError("Failure to create cert or key");
        destroyX509Auth(auth);
        return NULL;
    }

}

void destroyX509Auth(X509CertHandle handle) {
    if (handle != NULL) {
        X509Auth* auth = (X509Auth*) handle;
        if (auth->key != NULL) {
            if (auth->key->pkey != NULL) {
               EVP_PKEY_free(auth->key->pkey); // This will also free RSA struct
               auth->key->pkey = NULL;
               auth->key->rsaKey = NULL;
            }

            if (auth->key->fKeyPath != NULL) {
                free((void*)auth->key->fKeyPath);
                auth->key->fKeyPath = NULL;
            }

            free((void*)auth->key);
            auth->key = NULL;
        }

        if (auth->cert != NULL) {
            if (auth->cert->x509 != NULL) {
                X509_free(auth->cert->x509);
                auth->cert->x509 = NULL;
            }

            if (auth->cert->fCertPath != NULL) {
                free((void*)auth->cert->fCertPath);
                auth->cert->fCertPath = NULL;
            }

            if (auth->cert->thumbPrint != NULL) {
                free((void*)auth->cert->thumbPrint);
                auth->cert->thumbPrint = NULL;
            }

            free((void*)auth->cert);
            auth->cert = NULL;
        }

        free((void*)auth);
        auth = NULL;

    }
}

char* getCert(X509CertHandle handle) {
    if (handle != NULL) {
        X509Auth* auth = (X509Auth*)handle;
        return auth->cert->fCertPath;
    }
    else {
        LogError("Handle cannot be NULL");
        return NULL;
    }
}

unsigned char* getThumbPrint(X509CertHandle handle) {
    if (handle != NULL) {
        X509Auth* auth = (X509Auth*)handle;
        return auth->cert->thumbPrint;
    }
    else {
        LogError("Handle cannot be NULL");
        return NULL;
    }
}

char* getRSAKey(X509CertHandle handle) {

    if (handle != NULL) {
        X509Auth* auth = (X509Auth*)handle;
        return auth->key->fKeyPath;
    }
    else {
        LogError("Handle cannot be NULL");
        return NULL;
    }
}
