#ifndef _LMF_MESSAGE_H
#define _LMF_MESSAGE_H

typedef struct _LMF_MESSAGE_STRUCT {
	LMF_SIGNATURE signature;
	int64_t time;
	LMF_HASH last_hash;
	uint8_t type;
	uint32_t data_size;
	void* data;
} * LMF_MESSAGE;

typedef struct _LMF_OUTBOUND_MESSAGE {
	uint8_t type;
	uint32_t data_size;
	void* data;
	int64_t inbound_time;
	uint8_t inbound_type;
	uint32_t inbound_size;
	void* inbound_data;
} * LMF_OUTBOUND_MESSAGE;


#endif
