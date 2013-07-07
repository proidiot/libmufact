#ifndef _LMF_ENCRYPT_H
#define _LMF_ENCRYPT_H

typedef struct _LMF_DECRYPTED_STRUCT {
	LMF_SIGNATURE current_sig;
	LMF_BUNDLE_TYPE type;
	LMF_TIMESTAMP timestamp;
	LMF_KEY_ID id;
	LMF_HASH previous_hash;
	LMF_BYTE data[];
} * LMF_DECRYPTED;

LMF_B64* lmf_encrypt(
		size_t* encrypted_data_size,
		LMF_KEY_ID my_key_id,
		LMF_PRIVATE_KEY my_private_key,
		LMF_PUBLIC_KEY their_public_key,
		LMF_HASH previous_hash,
		LMF_BYTE* data,
		LMF_BUNDLE_TYPE data_type,
		size_t data_size);

LMF_B64* lmf_encode(
		size_t* encoded_data_size,
		LMF_KEY_ID my_key_id,
		LMF_PRIVATE_KEY my_private_key,
		LMF_BYTE* data,
		LMF_BUNDLE_TYPE data_type,
		size_t data_size);

LMF_DECRYPTED lmf_decrypt(
		size_t* decrypted_data_size,
		LMF_PRIVATE_KEY my_private_key,
		LMF_B64* encrypted_data,
		size_t encrypted_data_size);

LMF_DECRYPTED lmf_decode(
		size_t* decoded_data_size,
		LMF_B64* encoded_data,
		size_t encoded_data_size);

LMF_HASH lmf_get_hash(
		LMF_DECRYPTED decrypted_data,
		size_t decrypted_data_size);


#endif
