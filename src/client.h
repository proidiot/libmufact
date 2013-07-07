#ifndef _LMF_CLIENT_H
#define _LMF_CLIENT_H

#include <stdlib.h>
#include <stdint.h>

#ifndef _HAVE_BOOL_
#define bool short
#define true (1==1)
#define false (1==0)
#endif

typedef struct lmf_public_key_struct* lmf_public_key;
typedef struct lmf_private_key_struct* lmf_private_key;
typedef struct lmf_conversation_struct* lmf_conversation;
typedef struct lmf_outmsg_struct* lmf_outmsg;
typedef struct lmf_outresponse_struct* lmf_outresponse;
typedef struct lmf_response_issue_struct* lmf_response_issue;



/* private key decryption functions */
lmf_private_key decrypt_lmf_private_key(
		const void* const encrypted_key,
		const size_t encrypted_key_size,
		const void* const passphrase,
		const size_t passphrase_size);

lmf_private_key decrypt_lmf_private_key_file(
		const char* const encrypted_key_file,
		const void* const passphrase,
		const size_t passphrase_size);





/* conversation constructors with preloaded initial messages */
lmf_conversation revoke_key_lmf_conversation(
		const void* const received_data,
		const size_t received_data_size,
		const lmf_public_key server_master_key,
		const lmf_private_key client_key,
		const uint64_t client_key_id,
		const int64_t effective_time);

lmf_conversation update_key_lmf_conversation(
		const void* const received_data,
		const size_t received_data_size,
		const lmf_public_key server_master_key,
		const lmf_private_key old_client_key,
		const uint64_t client_key_id,
		const lmf_private_key new_client_key);

lmf_conversation register_key_lmf_conversation(
		const void* const received_data,
		const size_t received_data_size,
		const lmf_public_key server_master_key,
		const lmf_private_key client_key,
		const void* const registration_token,
		const size_t registration_token_size);

lmf_conversation reuse_key_lmf_conversation(
		const void* const received_data,
		const size_t received_data_size,
		const lmf_public_key server_master_key,
		const lmf_private_key client_key,
		const uint64_t client_key_id,
		const void* const registration_token,
		const size_t registration_token_size);

lmf_conversation get_lmf_conversation(
		const void* const received_data,
		const size_t received_data_size,
		const lmf_public_key server_master_key,
		const lmf_private_key client_key,
		const uint64_t client_key_id);


/* conversation destructor
 * this frees most everything other than data sent to and from the server (the
 * programmer will need to free those) and the keys (which could conceivably
 * be used in another conversation later, although it would probably be best to
 * wipe the unencrypted private key from memory for any kind of catchable
 * signal).
 */
bool destroy_lmf_conversation(lmf_conversation*);



/* message type ids */
#define LMF_MSGTYP_UNKNOWN 0
#define LMF_MSGTYP_ACK_UNKNOWN 1
#define LMF_MSGTYP_UNEXPECTED 2
#define LMF_MSGTYP_ACK_UNEXPECTED 3
#define LMF_MSGTYP_REVOKE 4
#define LMF_MSGTYP_ACK_REVOKE 5 /* Actually sending this is very unsecure. */
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
#define LMF_MSGTYP_REVOKE_TEMPS 16
#define LMF_MSGTYP_ACK_REVOKE_TEMPS 17
#define LMF_MSGTYP_GET 18
#define LMF_MSGTYP_ACK_GET 19 /* A belligerent server might send this. */
#define LMF_MSGTYP_REQUESTS 20
#define LMF_MSGTYP_ACK_REQUESTS 21
#define LMF_MSGTYP_RESPONSES 22
#define LMF_MSGTYP_ACK_RESPONSES 23
#define LMF_MSGTYP_EXHAUSTED 24 /* No more requests/responses to send. */
#define LMF_MSGTYP_ACK_EXHAUSTED 25
#define LMF_MSGTYP_RESPONSE_ISSUES 26
#define LMF_MSGTYP_ACK_RESPONSE_ISSUES 27

#ifdef __DISABLE_CHECK_ENFORCEMENT__
/* This function allows the programmer to use a switch instead of a series of
 * if-blocks, and although a switch could result in faster code, it would not
 * be feasible to programmatically enforce the check for a revoked key every
 * time, which could easily lead to a serious vulnerability. However, if the
 * programmer is already being careful to check for revoked and updated keys
 * and updated key ids at every new incoming message and if the check
 * enforcement has already been disabled to achieve a tiny performance boost,
 * then there is no reason not to use the message type directly.
 * */
uint8_t lmf_msg_type(const lmf_outmsg const);
#endif


/* message type checkers (only the client-specific ones) */
bool is_lmf_msg_unknown(const lmf_outmsg const);
bool is_lmf_msg_ack_unknown(const lmf_outmsg const);
bool is_lmf_msg_unexpected(const lmf_outmsg const);
bool is_lmf_msg_ack_unexpected(const lmf_outmsg const);
bool is_lmf_msg_revoke(const lmf_outmsg const);
bool is_lmf_msg_ack_revoke(const lmf_outmsg const); /* This must be handled. */
bool is_lmf_msg_update(const lmf_outmsg const);
bool is_lmf_msg_ack_update(const lmf_outmsg const); /* This must be handled. */
bool is_lmf_msg_register(const lmf_outmsg const);
bool is_lmf_msg_reuse(const lmf_outmsg const);
bool is_lmf_msg_ack_assign(const lmf_outmsg const); /*This should be handled.*/
bool is_lmf_msg_ack_update_temp(const lmf_outmsg const);
bool is_lmf_msg_ack_revoke_temps(const lmf_outmsg const);
bool is_lmf_msg_get(const lmf_outmsg const);
bool is_lmf_msg_ack_requests(const lmf_outmsg const);
bool is_lmf_msg_responses(const lmf_outmsg const);
bool is_lmf_msg_exhausted(const lmf_outmsg const);
bool is_lmf_msg_ack_exhausted(const lmf_outmsg const);
bool is_lmf_msg_ack_response_issues(const lmf_outmsg const);


/* message loop functions */
lmf_outmsg next_lmf_outmsg(const lmf_conversation);
bool is_lmf_msg_ready(const lmf_outmsg);
void* output_lmf_outmsg(
		size_t* output_size,
		const lmf_conversation,
		const lmf_outmsg);
char* output_lmf_outmsg_b64(const lmf_conversation, const lmf_outmsg);
bool input_lmf_inmsg(
		const lmf_conversation,
		const void* const input_data,
		const size_t input_size);
bool input_lmf_inmsg_b64(
		const lmf_conversation,
		const char* const input_string);
bool interject_lmf_msg_revoke(const int64_t effective_time);
bool interject_lmf_msg_update(const lmf_private_key new_client_key);


/* message loop data functions */
int64_t get_lmf_msg_effective_time(const lmf_outmsg const);
lmf_public_key get_master_lmf_public_key(const lmf_conversation const);
uint64_t get_client_key_id(const lmf_conversation const);
lmf_public_key get_temp_key(const lmf_conversation const);
lmf_public_key next_revoked_temp_key(
		int64_t* effective_time,
		const lmf_conversation);



/* response loop functions */
lmf_outresponse next_lmf_response(const lmf_conversation);
bool queue_lmf_response(const lmf_conversation, const lmf_outresponse);
unsigned int count_lmf_response_queue(const lmf_conversation const);
bool ignore_lmf_response(const lmf_conversation, const lmf_outresponse);

/* response loop data functions */
uint64_t get_lmf_request_id(const lmf_outresponse const);
uint64_t get_lmf_request_account_id(const lmf_outresponse const);
int64_t get_lmf_request_time(const lmf_outresponse const);
bool set_lmf_response_approval(const lmf_outresponse, bool approved);


/* response issue functions */
lmf_response_issue next_lmf_response_issue(const lmf_conversation);
char* describe_lmf_response_issue(const lmf_response_issue const);
uint64_t get_lmf_response_issue_request_id(const lmf_response_issue const);
lmf_outresponse get_offending_lmf_response(
		const lmf_conversation,
		const lmf_response_issue const);


#endif

