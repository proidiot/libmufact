#include "message_types.h"

#include <endian.h>

bool is_lmf_unknown_message(const lmf_outbound_message om)
{
	return om->type == LMF_UNKNOWN_MESSAGE_TYPE;
}




void* _encode_lmf_unexpected_message(
		uint32_t* encoded_length,
		const lmf_unexpected_message m)
{
	if (m == NULL) {
		return NULL;
	} else {
		return _encode_lmf_message_type_stack(
				encoded_length,
				m->expected);
	}
}

lmf_unexpected_message _decode_lmf_unexpected_message(
		const void* encoded,
		const uint32_t encoded_length)
{
	if (encoded == NULL || encoded_length == 0) {
		return (lmf_unexpected_message)NULL;
	}

	lmf_unexpected_message m = (lmf_unexpected_message)malloc(
			sizeof(struct _lmf_unexpected_message_struct));
	if (m != NULL) {
		m->expected = _decode_lmf_message_type_stack(
				encoded,
				encoded_length);
	}

	return m;
}

void* _encode_lmf_revoke_key_message(
		uint32_t* encoded_length,
		const lmf_revoke_key_message m)
{
	if (m == NULL) {
		return NULL;
	}

	void* encoded = malloc(sizeof(int64_t));
	if (encoded != NULL) {
		*(int64_t*)encoded = (int64_t)htobe64(
				(uint64_t)(m->effective_time));
		*encoded_length = sizeof(int64_t);
	}

	return encoded;
}

lmf_revoke_key_message _decode_lmf_revoke_key_message(
		const void* encoded,
		const uint32_t encoded_length)
{
	if (encoded == NULL || encoded_length < sizeof(int64_t)) {
		return (lmf_revoke_key_message)NULL;
	}

	lmf_revoke_key_message m = (lmf_revoke_key_message)malloc(
			sizeof(struct _lmf_revoke_key_message_struct));
	if (m != NULL) {
		m->effective_time = (int64_t)be64toh(*(uint64_t*)encoded);
	}

	return m;
}

void* _encode_lmf_update_key_message(
		uint32_t* encoded_length,
		const lmf_update_key_message m)
{
	if (m == NULL || m->new_key == NULL) {
		return NULL;
	}

	uint32_t encoded_key_length = 0;
	void* encoded_key = _encode_lmf_public_key(
			&encoded_key_length,
			m->new_key);
	if (encoded_key == NULL) {
		return NULL;
	}

	void* encoded = malloc(encoded_key_length + sizeof(int64_t));
	if (encoded != NULL) {
		*(int64_t*)encoded = (int64_t)htobe64(
				(uint64_t)(m->effective_time));
		memcpy(
				encoded + sizeof(int64_t),
				encoded_key,
				encoded_key_length);
		*encoded_length = encoded_key_length + sizeof(int64_t);
	}

	free(encoded_key);
	return encoded;
}

lmf_update_key_message _decode_lmf_update_key_message(
		const void* encoded,
		const uint32_t encoded_length)
{
	if (encoded == NULL || encoded_length < sizeof(int64_t)) {
		return (lmf_update_key_message)NULL;
	}

	lmf_public_key new_key = _decode_lmf_public_key(
			encoded + sizeof(int64_t),
			encoded_length - sizeof(int64_t));
	if (new_key == NULL) {
		return (lmf_update_key_message)NULL;
	}

	lmf_update_key_message m = (lmf_update_key_message)malloc(
			sizeof(struct _lmf_update_key_message_struct));
	if (m != NULL) {
		m->new_key = new_key;
		m->effective_time = (int64_t)be64toh(*(uint64_t)encoded);
	} else {
		free(new_key);
	}

	return m;
}

void* _encode_lmf_register_key_message(
		uint32_t* encoded_length,
		const lmf_register_key_message m)
{
	if (m == NULL || m->new_key == NULL || m->registration_token == NULL) {
		return NULL;
	}

	uint32_t encoded_key_length = 0;
	void* encoded_key = _encode_lmf_public_key(
			&encoded_key_length,
			m->new_key);
	if (encoded_key == NULL) {
		return NULL;
	}

	uint32_t encoded_token_length = 0;
	void* encoded_token = _encode_lmf_registration_token(
			&encoded_token_length,
			m->registration_token);
	if (encoded_token == NULL) {
		free(encoded_key);
		return NULL;
	}

	void* encoded = malloc(encoded_key_length + encoded_token_length);
	if (encoded != NULL) {
		memcpy(encoded, encoded_key, encoded_key_length);
		memcpy(
				encoded + encoded_key_length,
				encoded_token,
				encoded_token_length);
		*encoded_length = encoded_key_length + encoded_token_length;
	}

	free(encoded_key);
	free(encoded_token);
	return encoded;
}

lmf_register_key_message _decode_lmf_register_key_message(
		const void* encoded,
		const uint32_t encoded_length)
{
	if (encoded == NULL || encoded_length == 0) {
		return (lmf_register_key_message)NULL;
	}

	lmf_public_key new_key = _decode_lmf_public_key(
			encoded,
			encoded_length);
	if (encoded == NULL) {
		return (lmf_register_key_message)NULL;
	}

	//TODO: definitely need a better way to find the offset than this!
	uint32_t encoded_key_length = 0;
	void* encoded_key = _encode_lmf_public_key(
			&encoded_key_length,
			new_key);
	if (encoded_key == NULL) {
		free(new_key);
		return (lmf_register_key_message)NULL;
	} else {
		free(encoded_key);
	}

	lmf_registration_token token = _decode_lmf_registration_token(
			encoded + encoded_key_length,
			encoded_length - encoded_key_length);
	if (token == NULL) {
		free(new_key);
		return (lmf_register_key_message)NULL;
	}

	lmf_register_key_message m = (lmf_register_key_message)malloc(
			sizeof(struct _lmf_register_key_message));
	if (m != NULL) {
		m->new_key = new_key;
		m->registration_token = token;
	} else {
		free(new_key);
		free(token);
	}

	return m;
}



