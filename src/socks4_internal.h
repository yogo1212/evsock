#ifndef SOCKS4_INTERNAL_H
#define SOCKS4_INTERNAL_H

#define SOCKS4_REQ_VERSION 0x04

typedef struct __attribute__((__packed__)) {
	uint8_t version;
	uint8_t command;
	uint16_t port;
	uint32_t ip; // TODO right type
	uint8_t user_id_null;
} socks4_req_hdr_t;

#define SOCKS4_RESP_VERSION 0x00

#define SOCKS4_RESP_STATUS_GRANTED    0x5A
#define SOCKS4_RESP_STATUS_FAILED     0x5B
#define SOCKS4_RESP_STATUS_NO_IDENTD  0x5C
#define SOCKS4_RESP_STATUS_IDENTD_ERR 0x5D

typedef struct __attribute__((__packed__)) {
	uint8_t version;
	uint8_t status;
	uint16_t port;
	uint32_t ip; // TODO right type
} socks4_resp_hdr_t;

#endif