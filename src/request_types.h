#ifndef _LMF_REQUEST_TYPES_H
#define _LMF_REQUEST_TYPES_H

typedef struct _LMF_REQUEST_STRUCT {
	LMF_REQUEST_ID id;
	LMF_SITE_ID site_id;
	int64_t time;
	uint8_t type;
	uint32_t data_len;
	void* data;
} * LMF_REQUEST;

#define LMF_SIMPLE_REQUEST_TYPE 0

#endif
