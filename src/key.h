#ifndef _LMF_KEY_H
#define _LMF_KEY_H

#ifdef HAVE_LIBCRYPTO

#include <openssl/pem.h>

typedef RSA* LMF_PUBLIC_KEY;

typedef RSA* LMF_PRIVATE_KEY;

#endif

typedef uint64_t LMF_KEY_ID;

LMF_PUBLIC_KEY lmf_get_public_key(LMF_BYTE* data, size_t data_size);

LMF_PRIVATE_KEY lmf_get_private_key(LMF_BYTE* data, size_t data_size);

#endif
