#ifndef _LMF_CLIENT_H
#define _LMF_CLIENT_H

LMF_CONVERSATION lmf_start_conversation(
		const LMF_PUBLIC_KEY server_master_key,
		const LMF_KEY_ID client_key_id,
		const LMF_PRIVATE_KEY client_private_key,
		const LMF_B64* received_data,
		const size_t received_data_size);

LMF_B64* lmf_register_key(
		size_t* output_size,
		LMF_CONVERSATION conversation,
		const LMF_REGISTRATION_TOKEN token,
		const LMF_PUBLIC_KEY client_public_key);

LMF_B64* lmf_reuse_key(
		size_t* output_size,
		LMF_CONVERSATION conversation,
		const LMF_REGISTRATION_TOKEN token);

LMF_B64* lmf_update_key(
		size_t* output_size,
		LMF_CONVERSATION conversation,
		const LMF_PUBLIC_KEY client_new_public_key);

LMF_B64* lmf_revoke_key(
		size_t* output_size,
		LMF_CONVERSATION conversation,
		const LMF_TIMESTAMP effective_time);

LMF_B64* lmf_acknowledge(size_t* output_size, LMF_CONVERSATION conversation);

LMF_B64* lmf_get_requests(size_t* output_size, LMF_CONVERSATION conversation);

LMF_B64* lmf_send_responses(
		size_t* output_size,
		LMF_CONVERSATION conversation);

#endif
