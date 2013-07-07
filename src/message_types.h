#ifndef _LMF_MESSAGE_TYPES_H
#define _LMF_MESSAGE_TYPES_H

#include "crypto.h"
#include "request_types.h"
#include "response_types.h"


#define LMF_MSGTYP_UNKNOWN 0
#define LMF_MSGTYP_ACK_UNKNOWN 1
#define LMF_MSGTYP_UNEXPECTED 2
#define LMF_MSGTYP_ACK_UNEXPECTED 3
#define LMF_MSGTYP_REVOKE 4
#define LMF_MSGTYP_ACK_REVOKE 5 /* Sending this is insecure. */
#define LMF_MSGTYP_UPDATE 6
#define LMF_MSGTYP_ACK_UPDATE 7
#define LMF_MSGTYP_REGISTER 8
#define LMF_MSGTYP_ACK_REGISTER 9
#define LMF_MSGTYP_REUSE 10
#define LMF_MSGTYP_ACK_REUSE 11
#define LMF_MSGTYP_ASSIGN 12
#define LMF_MSGTYP_ACK_ASSIGN 13
#define LMF_MSGTYP_UPDATE_TEMP 14
#define LMF_MSGTYP_ACK_UPDATE_TEMP 15
#define LMF_MSGTYP_REVOKE_TEMP 16
#define LMF_MSGTYP_ACK_REVOKE_TEMP 17
#define LMF_MSGTYP_GET 18
#define LMF_MSGTYP_ACK_GET 19 /* A belligerent server might send this. */
#define LMF_MSGTYP_REQUESTS 20
#define LMF_MSGTYP_ACK_REQUESTS 21
#define LMF_MSGTYP_RESPONSES 22
#define LMF_MSGTYP_ACK_RESPONSES 23
#define LMF_MSGTYP_EXHAUSTED 24 /* No more requests/responses to send. */
#define LMF_MSGTYP_ACK_EXHAUSTED 25
#define LMF_MSGTYP_ISSUES 26 /* This was needed to report response issues. */
#define LMF_MSGTYP_ACK_ISSUES 27


bool is_lmf_msg_unknown(const lmf_outmsg m);
bool is_lmf_msg_ack_unknown(const lmf_outmsg m);
bool is_lmf_msg_unexpected(const lmf_outmsg m);
bool is_lmf_msg_ack_unexpected(const lmf_outmsg m);
bool is_lmf_msg_revoke(const lmf_outmsg m);
bool is_lmf_msg_ack_revoke(const lmf_outmsg m); /* This must be handled. */
bool is_lmf_msg_update(const lmf_outmsg m);
bool is_lmf_msg_ack_update(const lmf_outmsg m); /* This must be handled. */
bool is_lmf_msg_register(const lmf_outmsg m);
bool is_lmf_msg_ack_register(const lmf_outmsg m);
bool is_lmf_msg_reuse(const lmf_outmsg m);
bool is_lmf_msg_ack_reuse(const lmf_outmsg m);
bool is_lmf_msg_assign(const lmf_outmsg m);
bool is_lmf_msg_ack_assign(const lmf_outmsg m); /* This should be handled. */
bool is_lmf_msg_update_temp(const lmf_outmsg m);
bool is_lmf_msg_ack_update_temp(const lmf_outmsg m);
bool is_lmf_msg_revoke_temp(const lmf_outmsg m);
bool is_lmf_msg_ack_revoke_temp(const lmf_outmsg m);
bool is_lmf_msg_get(const lmf_outmsg m);
bool is_lmf_msg_ack_get(const lmf_outmsg m);
bool is_lmf_msg_requests(const lmf_outmsg m);
bool is_lmf_msg_ack_requests(const lmf_outmsg m);
bool is_lmf_msg_responses(const lmf_outmsg m);
bool is_lmf_msg_ack_responses(const lmf_outmsg m);
bool is_lmf_msg_exhausted(const lmf_outmsg m);
bool is_lmf_msg_ack_exhausted(const lmf_outmsg m);
bool is_lmf_msg_issues(const lmf_outmsg m);
bool is_lmf_msg_ack_issues(const lmf_outmsg m);


typedef struct _lmf_msgdat_unexpected_struct {
	lmf_msgtyp_stack expected;
} * lmf_msgdat_unexpected;
void* _encode_lmf_msgdat_unexpected(
		uint32_t* encoded_length,
		const LMF_UNEXPECTED_MESSAGE m);
LMF_UNEXPECTED_MESSAGE _decode_LMF_UNEXPECTED_MESSAGE(
		const void* encoded,
		const uint32_t encoded_length);

typedef struct _LMF_REVOKE_KEY_MESSAGE_STRUCT {
	int64_t effective_time;
} * LMF_REVOKE_KEY_MESSAGE;
void* _encode_LMF_REVOKE_KEY_MESSAGE(
		uint32_t* encoded_length,
		const LMF_REVOKE_KEY_MESSAGE m);
LMF_REVOKE_KEY_MESSAGE _decode_LMF_REVOKE_KEY_MESSAGE(
		const void* encoded,
		const uint32_t encoded_length);

typedef struct _LMF_UPDATE_KEY_MESSAGE_STRUCT {
	LMF_PUBLIC_KEY new_key;
	int64_t effective_time;
} * LMF_UPDATE_KEY_MESSAGE;
void* _encode_LMF_UPDATE_KEY_MESSAGE(
		uint32_t* encoded_length,
		const LMF_UPDATE_KEY_MESSAGE m);
LMF_UPDATE_KEY_MESSAGE _decode_LMF_UPDATE_KEY_MESSAGE(
		const void* encoded,
		const uint32_t encoded_length);

typedef struct _LMF_REGISTER_KEY_MESSAGE_STRUCT {
	LMF_PUBLIC_KEY new_key;
	LMF_REGISTRATION_TOKEN registration_token;
} * LMF_REGISTER_KEY_MESSAGE;
void* _encode_LMF_REGISTER_KEY_MESSAGE(
		uint32_t* encoded_length,
		const LMF_REGISTER_KEY_MESSAGE m);
LMF_REGISTER_KEY_MESSAGE _decode_LMF_REGISTER_KEY_MESSAGE(
		const void* encoded,
		const uint32_t encoded_length);

typedef struct _LMF_REUSE_KEY_MESSAGE_STRUCT {
	LMF_REGISTRATION_TOKEN registration_token;
} * LMF_REUSE_KEY_MESSAGE;
void* _encode_LMF_REUSE_KEY_MESSAGE(
		uint32_t* encoded_length,
		const LMF_REUSE_KEY_MESSAGE m);
LMF_REUSE_KEY_MESSAGE _decode_LMF_REUSE_KEY_MESSAGE(
		const void* encoded,
		const uint32_t encoded_length);

typedef struct _LMF_ASSIGN_KEY_ID_MESSAGE_STRUCT {
	LMF_KEY_ID key_id;
} * LMF_ASSIGN_KEY_ID_MESSAGE;
void* _encode_LMF_ASSIGN_KEY_ID_MESSAGE(
		uint32_t* encoded_length,
		const LMF_ASSIGN_KEY_ID_MESSAGE m);
LMF_ASSIGN_KEY_ID_MESSAGE _decode_LMF_ASSIGN_KEY_ID_MESSAGE(
		const void* encoded,
		const uint32_t encoded_length);

typedef struct _LMF_UPDATE_TEMP_KEY_MESSAGE_STRUCT {
	LMF_PUBLIC_KEY new_key;
	int64_t effective_time;
} * LMF_UPDATE_TEMP_KEY_MESSAGE;
void* _encode_LMF_UPDATE_TEMP_KEY_MESSAGE(
		uint32_t* encoded_length,
		const LMF_UPDATE_TEMP_KEY_MESSAGE m);
LMF_UPDATE_TEMP_KEY_MESSAGE _decode_LMF_UPDATE_TEMP_KEY_MESSAGE(
		const void* encoded,
		const uint32_t encoded_length);

typedef struct _LMF_REVOKE_TEMP_KEYS_MESSAGE_STRUCT {
	LMF_PUBLIC_KEY new_key;
	/* effective time of new temp key, revoked effective times in stack */
	int64_t effective_time;
	LMF_REVOKE_TEMP_KEY_STACK revoked_temp_keys;
} * LMF_REVOKE_TEMP_KEYS_MESSAGE;
void* _encode_LMF_REVOKE_TEMP_KEYS_MESSAGE(
		uint32_t* encoded_length,
		const LMF_REVOKE_TEMP_KEYS_MESSAGE m);
LMF_REVOKE_TEMP_KEYS_MESSAGE _decode_LMF_REVOKE_TEMP_KEYS_MESSAGE(
		const void* encoded,
		const uint32_t encoded_length);


typedef struct _LMF_REQUESTS_MESSAGE_STRUCT {
	LMF_REQUEST_STACK requests;
} * LMF_REQUESTS_MESSAGE;
void* _encode_LMF_REQUESTS_MESSAGE(
		uint32_t* encoded_length,
		const LMF_REQUESTS_MESSAGE m);
LMF_REQUESTS_MESSAGE _decode_LMF_REQUESTS_MESSAGE(
		const void* encoded,
		const uint32_t encoded_length);

typedef struct _LMF_RESPONSES_MESSAGE_STRUCT {
	LMF_RESPONSE_STACK responses;
} * LMF_RESPONSES_MESSAGE;
void* _encode_LMF_RESPONSES_MESSAGE(
		uint32_t* encoded_length,
		const LMF_RESPONSES_MESSAGE m);
LMF_RESPONSES_MESSAGE _decode_LMF_RESPONSES_MESSAGE(
		const void* encoded,
		const uint32_t encoded_length);


typedef struct _LMF_RESPONSE_ISSUES_MESSAGE_STRUCT {
	LMF_RESPONSE_ISSUE_STACK issues;
} * LMF_RESPONSE_ISSUES_MESSAGE;
void* _encode_LMF_RESPONSE_ISSUES_MESSAGE(
		uint32_t* encoded_length,
		const LMF_RESPONSE_ISSUES_MESSAGE m);
LMF_RESPONSE_ISSUES_MESSAGE _decode_LMF_RESPONSE_ISSUES_MESSAGE(
		const void* encoded,
		const uint32_t encoded_length);

#endif

