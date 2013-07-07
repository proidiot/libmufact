#ifndef _LMF_CRYPTO_H
#define _LMF_CRYPTO_H

#ifdef HAVE_LIBCRYPTO

#include <openssl/rsa.h>
#include <openssl/sha.h>

typedef RSA* LMF_PUBLIC_KEY;
typedef RSA* LMF_PRIVATE_KEY;
typedef unsigned char* LMF_HASH;

#endif

#endif
