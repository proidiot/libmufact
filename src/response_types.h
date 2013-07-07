#ifndef _LMF_RESPONSE_TYPES_H
#define _LMF_RESPONSE_TYPES_H

typedef struct _LMF_OUTBOUND_RESPONSE_STRUCT {
	LMF_REQUEST_ID id;
	LMF_SITE_ID site_id;
	bool send;
	uint8_t type;
	uint32_t data_size;
	void* data;
	LMF_REQUEST request;
} * LMF_OUTBOUND_RESPONSE;


typedef struct _LMF_RESPONSE_STRUCT {
	LMF_REQUEST_ID id;
	LMF_SITE_ID site_id;
	uint8_t type;
	uint32_t data_size;
	void* data;
} * LMF_RESPONSE;

#define LMF_UNKNOWN_RESPONSE_TYPE 0

#define LMF_SIMPLE_RESPONSE_TYPE 1

#endif
