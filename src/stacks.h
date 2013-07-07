#ifndef _LMF_STACKS_H
#define _LMF_STACKS_H

typedef struct _LMF_MESSAGE_TYPE_STACK_STRUCT {
	uint8_t type;
	struct _LMF_MESSAGE_TYPE_STACK_STRUCT* next;
} * LMF_MESSAGE_TYPE_STACK;
LMF_MESSAGE_TYPE_STACK new_LMF_MESSAGE_TYPE_STACK();
LMF_MESSAGE_TYPE_STACK push_LMF_MESSAGE_TYPE(
		LMF_MESSAGE_TYPE_STACK types,
		const uint8_t type);
uint8_t pop_LMF_MESSAGE_TYPE(LMF_MESSAGE_TYPE_STACK types);
BOOL contains_LMF_MESSAGE_TYPE(
		const LMF_MESSAGE_TYPE_STACK types,
		const uint8_t type);
BOOL empty_LMF_MESSAGE_TYPE_STACK(const LMF_MESSAGE_TYPE_STACK types);
#define gen_LMF_MESSAGE_TYPES(...) STACKER( \
		push_LMF_MESSAGE_TYPE,NULL,__VA_ARGS__)
void* _encode_LMF_MESSAGE_TYPE_STACK(
		uint32_t* encoded_length,
		const LMF_MESSAGE_TYPE_STACK types);
LMF_MESSAGE_TYPES _decode_LMF_MESSAGE_TYPE_STACK(
		const void* encoded,
		const uint32_t encoded_length);

typedef struct _LMF_RESPONSE_TYPE_STACK_STRUCT {
	uint8_t type;
	struct _LMF_RESPONSE_TYPE_STACK_STRUCT* next;
} * LMF_RESPONSE_TYPE_STACK;
LMF_RESPONSE_TYPE_STACK new_LMF_RESPONSE_TYPE_STACK();
LMF_RESPONSE_TYPE_STACK push_LMF_RESPONSE_TYPE(
		LMF_RESPONSE_TYPE_STACK types,
		const uint8_t type);
uint8_t pop_LMF_RESPONSE_TYPE(LMF_RESPONSE_TYPE_STACK types);
BOOL contains_LMF_RESPONSE_TYPE(
		const LMF_RESPONSE_TYPE_STACK types,
		const uint8_t type);
BOOL empty_LMF_RESPONSE_TYPE_STACK(const LMF_RESPONSE_TYPE_STACK types);
#define gen_LMF_RESPONSE_TYPES(...) STACKER( \
		push_LMF_RESPONSE_TYPE,NULL,__VA_ARGS__)
void* _encode_LMF_RESPONSE_TYPE_STACK(
		uint32_t* encoded_length,
		const LMF_RESPONSE_TYPE_STACK types);
LMF_RESPONSE_TYPES _decode_LMF_RESPONSE_TYPE_STACK(
		const void* encoded,
		const uint32_t encoded_length);


typedef struct _LMF_REQUEST_STACK_STRUCT {
	LMF_REQUEST request;
	struct _LMF_REQUEST_STACK* next;
} * LMF_REQUEST_STACK;
LMF_REQUEST_STACK new_LMF_REQUEST_STACK();
LMF_REQUEST_STACK push_LMF_REQUEST(
		LMF_REQUEST_STACK requests,
		LMF_REQUEST request);
LMF_REQUEST pop_LMF_REQUEST(LMF_REQUEST_STACK requests);
BOOL contains_LMF_REQUEST(
		const LMF_REQUEST_STACK requests,
		const LMF_REQUEST request);
BOOL empty_LMF_REQUEST_STACK(const LMF_REQUEST_STACK requests);
void* _encode_LMF_REQUEST_STACK(
		uint32_t* encoded_length,
		const LMF_REQUEST_STACK requests);
LMF_REQUEST_STACK _decode_LMF_REQUEST_STACK(
		const void* encoded,
		const uint32_t encoded_length);


typedef struct _LMF_RESPONSE_STACK_STRUCT {
	LMF_RESPONSE response;
	struct _LMF_RESPONSE_STACK_STRUCT* next;
} * LMF_RESPONSE_STACK;
LMF_RESPONSE_STACK new_LMF_RESPONSE_STACK();
LMF_RESPONSE_STACK push_LMF_RESPONSE(
		LMF_RESPONSE_STACK responses,
		LMF_RESPONSE response);
LMF_RESPONSE pop_LMF_RESPONSE(LMF_RESPONSE_STACK responses);
BOOL contains_LMF_RESPONSE(
		const LMF_RESPONSE_STACK responses,
		const LMF_RESPONSE response);
BOOL empty_LMF_RESPONSE_STACK(const LMF_RESPONSE_STACK responses);
void* _encode_LMF_RESPONSE_STACK(
		uint32_t* encoded_length,
		const LMF_RESPONSE_STACK responses);
LMF_RESPONSE_STACK _decode_LMF_RESPONSE_STACK(
		const void* encoded,
		uint32_t encoded_length);


typedef struct _LMF_RESPONSE_ISSUE_STACK_STRUCT {
	LMF_RESPONSE_ISSUE issue;
	struct _LMF_RESPONSE_ISSUE_STACK_STRUCT* next;
} * LMF_RESPONSE_ISSUE_STACK;
LMF_RESPONSE_ISSUE_STACK new_LMF_RESPONSE_ISSUE_STACK();
LMF_RESPONSE_ISSUE_STACK push_LMF_RESPONSE_ISSUE(
		LMF_RESPONSE_ISSUE_STACK issues,
		LMF_RESPONSE_ISSUE issue);
LMF_RESPONSE_ISSUE pop_LMF_RESPONSE_ISSUE(LMF_RESPONSE_ISSUE_STACK issues);
BOOL contains_LMF_RESPONSE_ISSUE(
		const LMF_RESPONSE_ISSUE_STACK issues,
		const LMF_RESPONSE_ISSUE issue);
BOOL empty_LMF_RESPONSE_ISSUE_STACK(const LMF_RESPONSE_ISSUE_STACK issues);
void* _encode_LMF_RESPONSE_ISSUE_STACK(
		uint32_t* encoded_length,
		const LMF_RESPONSE_ISSUE_STACK issues);
LMF_RESPONSE_ISSUE_STACK _decode_LMF_RESPONSE_ISSUE_STACK(
		const void* encoded,
		const uint32_t encoded_length);


typedef struct _LMF_REVOKE_TEMP_KEY_STACK_STRUCT {
	LMF_PUBLIC_KEY key;
	int64_t effective_time;
	struct _LMF_REVOKE_TEMP_KEY_STACK_STRUCT* next;
} * LMF_REVOKE_TEMP_KEY_STACK;
LMF_REVOKE_TEMP_KEY_STACK new_LMF_REVOKE_TEMP_KEY_STACK();
LMF_REVOKE_TEMP_KEY_STACK push_revoked_temp_LMF_PUBLIC_KEY(
		LMF_REVOKE_TEMP_KEY_STACK keys,
		LMF_PUBLIC_KEY key,
		int64_t effective_time);
LMF_PUBLIC_KEY pop_revoked_temp_LMF_PUBLIC_KEY(
		int64_t* effective_time,
		LMF_REVOKE_TEMP_KEY_STACK keys);
BOOL contains_revoked_temp_LMF_PUBLIC_KEY(
		const LMF_REVOKE_TEMP_KEY_STACK keys,
		const LMF_PUBLIC_KEY key);
BOOL empty_LMF_REVOKE_TEMP_KEY_STACK(const LMF_REVOKE_TEMP_KEY_STACK keys);
void* _encode_LMF_REVOKE_TEMP_KEY_STACK(
		uint32_t* encoded_length,
		const LMF_REVOKE_TEMP_KEY_STACK keys);
LMF_REVOKE_TEMP_KEY_STACK _decode_LMF_REVOKE_TEMP_KEY_STACK(
		const void* encoded,
		const uint32_t encoded_length);


#endif
