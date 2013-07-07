#ifndef _LMF_BUNDLE_H
#define _LMF_BUNDLE_H

#include "common_macros.h"

#define _LMF_BUNDLE_TYPE_PROTO(n,...) typedef struct _##n##_STRUCT {\
	APPEND_SEMICOLONS(__VA_ARGS__)} * n;\
n decode_##n(const LMF_BYTE* data, const size_t data_size);\
LMF_BYTE* encode_##n(size_t* data_size, const n bundle);

typedef LMF_BYTE LMF_BUNDLE_TYPE;

/* very very bad... also special handling of timestamp */
#define LMF_REVOKE_KEY_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x00
_LMF_BUNDLE_TYPE_PROTO(LMF_REVOKE_KEY_BUNDLE);

/* not so bad... also special handling of timestamp */
#define LMF_UPDATE_KEY_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x01
_LMF_BUNDLE_TYPE_PROTO(LMF_UPDATE_KEY_BUNDLE, LMF_PUBLIC_KEY pubkey);

/* very bad... also special handling of timestamp */
#define LMF_REVOKE_UPDATE_TEMP_KEY_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x02
_LMF_BUNDLE_TYPE_PROTO(
		LMF_REVOKE_UPDATE_TEMP_KEY_BUNDLE,
		LMF_PUBLIC_KEY pubkey);

/* not so bad... also special handling of timestamp */
#define LMF_UPDATE_TEMP_KEY_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x03
_LMF_BUNDLE_TYPE_PROTO(LMF_UPDATE_TEMP_KEY_BUNDLE, LMF_PUBLIC_KEY pubkey);

/*
 * Reserved for future use.
 */
#define LMF_REPORT_REVOKED_USE_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x04

/*
 * Reserved for future use.
 */
#define LMF_REPORT_REVOKED_TEMP_USE_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x05

/*
 * NOTE: This circumstance could be a potential security breach,
 * so if the server refuses to respond to potential security breaches,
 * a bundle of this type might not ever be sent.
 */
#define LMF_FUTURE_TIMESTAMP_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x06
_LMF_BUNDLE_TYPE_PROTO(LMF_FUTURE_TIMESTAMP_BUNDLE);

/*
 * NOTE: This circumstance could be a potential security breach,
 * so if the server refuses to respond to potential security breaches,
 * a bundle of this type might not ever be sent.
 */
#define LMF_OLD_TIMESTAMP_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x07
_LMF_BUNDLE_TYPE_PROTO(LMF_OLD_TIMESTAMP_BUNDLE);

/*
 * NOTE: This circumstance could be a potential security breach,
 * so if the server refuses to respond to potential security breaches,
 * a bundle of this type might not ever be sent.
 */
#define LMF_BAD_HASH_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x08
_LMF_BUNDLE_TYPE_PROTO(LMF_BAD_HASH_BUNDLE);

/*
 * NOTE: This circumstance could be a potential security breach,
 * so if the server refuses to respond to potential security breaches,
 * a bundle of this type might not ever be sent.
 */
#define LMF_BAD_SIGNATURE_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x09
_LMF_BUNDLE_TYPE_PROTO(LMF_BAD_SIGNATURE_BUNDLE);

/*
 * some bundle type specified beyond the highest known
 * (any lower type should be known since later types are defined with
 * increasing value)
 */
#define LMF_UNKNOWN_BUNDLE_TYPE_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x0A
_LMF_BUNDLE_TYPE_PROTO(
		LMF_UNKNOWN_BUNDLE_TYPE_BUNDLE,
		LMF_BUNDLE_TYPE highest_recognized_type_id);

/*
 * register a brand new public key... the key id is ignored
 */
#define LMF_REGISTER_KEY_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x0B
_LMF_BUNDLE_TYPE_PROTO(
		LMF_REGISTER_KEY_BUNDLE,
		LMF_REGISTRATION_TOKEN token,
		LMF_PUBLIC_KEY pubkey);

/*
 * use a previously registerred key for another site
 */
#define LMF_REUSE_KEY_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x0C
_LMF_BUNDLE_TYPE_PROTO(LMF_REUSE_KEY_BUNDLE, LMF_REGISTRATION_TOKEN token);

/*
 * assign the key just used a new id (or possibly reassign it?)
 */
#define LMF_ASSIGN_KEY_ID_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x0D
_LMF_BUNDLE_TYPE_PROTO(LMF_ASSIGN_KEY_ID_BUNDLE, LMF_KEY_ID id);

/*
 * acknowledging the last bundle
 * (this means different things in different circumstances)
 */
#define LMF_ACKNOWLEDGE_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x0E
_LMF_BUNDLE_TYPE_PROTO(LMF_ACKNOWLEDGE_BUNDLE);

/*
 * get any queued requests for this key id
 */
#define LMF_GET_REQUESTS_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x0F
_LMF_BUNDLE_TYPE_PROTO(LMF_GET_REQUESTS_BUNDLE);

/*
 * i've sent all the requests/responses i have ready for you,
 * but keep sending me any more requests/responses you may have just as before
 */
#define LMF_NO_MORE_ITEMS_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x10
_LMF_BUNDLE_TYPE_PROTO(LMF_NO_MORE_ITEMS_BUNDLE);

/* 
 * you sent a wrong bundle type in reply to the last thing i sent you
 * */
#define LMF_UNACCEPTABLE_REPLY_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x11
_LMF_BUNDLE_TYPE_PROTO(
		LMF_UNACCEPTABLE_REPLY_BUNDLE,
		LMF_BUNDLE_TYPE_STACK acceptable_types);

/*
 * a collection of requests
 */
#define LMF_REQUESTS_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x12
_LMF_BUNDLE_TYPE_PROTO(LMF_REQUESTS_BUNDLE, LMF_REQUEST_STACK requests);

/*
 * a collection of responses
 */
#define LMF_RESPONSES_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x13
_LMF_BUNDLE_TYPE_PROTO(LMF_RESPONSES_BUNDLE, LMF_RESPONSE_STACK responses);

/*
 * i don't know one or more of the request types you sent
 */
#define LMF_UNKNOWN_REQUEST_TYPES_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x14
_LMF_BUNDLE_TYPE_PROTO(
		LMF_UNKNOWN_REQUEST_TYPES_BUNDLE,
		LMF_REQUEST_ID_STACK ids,
		LMF_REQUEST_TYPE_STACK known_types);

/*
 * i don't know one or more of the response types you sent
 */
#define LMF_UNKNOWN_RESPONSE_TYPES_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x15
_LMF_BUNDLE_TYPE_PROTO(
		LMF_UNKNOWN_RESPONSE_TYPES_BUNDLE,
		LMF_REQUEST_ID_STACK ids,
		LMF_RESPONSE_TYPE_STACK known_types);

/*
 * you sent the wrong response type for one or more of the requests i sent you
 */
#define LMF_UNACCEPTABLE_RESPONSES_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x16
_LMF_BUNDLE_TYPE_PROTO(
		LMF_UNACCEPTABLE_RESPONSES_BUNDLE,
		LMF_ACCEPTABLE_RESPONSES_STACK acceptable_responses);

/*
 * you sent a response for one or more requests that have expired
 */
#define LMF_EXPIRED_REQUESTS_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x17
_LMF_BUNDLE_TYPE_PROTO(LMF_EXPIRED_REQUESTS_BUNDLE, LMF_REQUEST_ID_STACK ids);

/*
 * unable to produce one of the request/response types listed as acceptable for
 * one or more requests
 */
#define LMF_UNRESOLVABLE_REQUEST_BUNDLE_TYPE (LMF_BUNDLE_TYPE)0x18
_LMF_BUNDLE_TYPE_PROTO(
		LMF_UNRESOLVABLE_REQUEST_BUNDLE,
		LMF_REQUEST_ID_STACK ids);


#endif
