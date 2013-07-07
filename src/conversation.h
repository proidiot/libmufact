#ifndef _LMF_CONVERSATION_H
#define _LMF_CONVERSATION_H

typedef struct _LMF_CONVERSATION_OPTIONS_STRUCT {
	BOOL send_revoked_reports;
	BOOL allow_master_key_update;
} * LMF_CONVERSATION_OPTIONS;

typedef struct _LMF_CONVERSATION_STRUCT {
	LMF_PUBLIC_KEY remote_key;
	LMF_PRIVATE_KEY local_key;
	LMF_KEY_ID local_key_id;
	LMF_HASH previous_hash;
	LMF_REQUEST_STACK handled_requests;
	LMF_REQUEST_STACK unhandled_requests;
	LMF_RESPONSE_STACK handled_responses;
	LMF_RESPONSE_STACK unhandled_responses;
} * LMF_CONVERSATION;

#endif
