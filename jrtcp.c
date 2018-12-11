#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

/*! \brief RTCP Packet Types (http://www.networksorcery.com/enp/protocol/rtcp.htm) */
typedef enum {
    RTCP_FIR = 192,
    RTCP_SR = 200,
    RTCP_RR = 201,
    RTCP_SDES = 202,
    RTCP_BYE = 203,
    RTCP_APP = 204,
    RTCP_RTPFB = 205,
    RTCP_PSFB = 206,
    RTCP_XR = 207,
} rtcp_type;
typedef rtcp_type janus_rtcp_type;

/*! \brief RTCP Header (http://tools.ietf.org/html/rfc3550#section-6.1) */
typedef struct rtcp_header
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t rc:5;
	uint16_t type:8;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rc:5;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:8;
#endif
	uint16_t length:16;
} rtcp_header;
typedef rtcp_header janus_rtcp_header;

/*! \brief RTCP REMB (http://tools.ietf.org/html/draft-alvestrand-rmcat-remb-03) */
typedef struct rtcp_remb
{
	/*! \brief Unique identifier ('R' 'E' 'M' 'B') */
	char id[4];
	/*! \brief Num SSRC, Br Exp, Br Mantissa (bit mask) */
	uint32_t bitrate;
	/*! \brief SSRC feedback (we expect at max three SSRCs in there) */
	uint32_t ssrc[3];
} rtcp_remb;
typedef rtcp_remb janus_rtcp_fb_remb;

/*! \brief RTCP-FB (http://tools.ietf.org/html/rfc4585) */
typedef struct rtcp_fb
{
	/*! \brief Common header */
	rtcp_header header;
	/*! \brief Sender SSRC */
	uint32_t ssrc;
	/*! \brief Media source */
	uint32_t media;
	/*! \brief Feedback Control Information */
	char fci[1];
} rtcp_fb;
typedef rtcp_fb janus_rtcp_fb;

/* Query an existing REMB message */
uint32_t janus_rtcp_get_remb(char *packet, int len) {
	if(packet == NULL || len == 0)
		return 0;
	janus_rtcp_header *rtcp = (janus_rtcp_header *)packet;
	if(rtcp->version != 2)
		return 0;
	/* Get REMB bitrate, if any */
	int total = len;
	while(rtcp) {
		if(rtcp->type == RTCP_PSFB) {
			int fmt = rtcp->rc;
			if(fmt == 15) {
				janus_rtcp_fb *rtcpfb = (janus_rtcp_fb *)rtcp;
				janus_rtcp_fb_remb *remb = (janus_rtcp_fb_remb *)rtcpfb->fci;
				if(remb->id[0] == 'R' && remb->id[1] == 'E' && remb->id[2] == 'M' && remb->id[3] == 'B') {
					/* FIXME From rtcp_utility.cc */
					unsigned char *_ptrRTCPData = (unsigned char *)remb;
					_ptrRTCPData += 4;	/* Skip unique identifier and num ssrc */
					//~ JANUS_LOG(LOG_VERB, " %02X %02X %02X %02X\n", _ptrRTCPData[0], _ptrRTCPData[1], _ptrRTCPData[2], _ptrRTCPData[3]);
					uint8_t brExp = (_ptrRTCPData[1] >> 2) & 0x3F;
					uint32_t brMantissa = (_ptrRTCPData[1] & 0x03) << 16;
					brMantissa += (_ptrRTCPData[2] << 8);
					brMantissa += (_ptrRTCPData[3]);
					uint32_t bitrate = brMantissa << brExp;
					// JANUS_LOG(LOG_HUGE, "Got REMB bitrate %"SCNu32"\n", bitrate);
					return bitrate;
				}
			}
		}
		/* Is this a compound packet? */
		int length = ntohs(rtcp->length);
		if(length == 0)
			break;
		total -= length*4+4;
		if(total <= 0)
			break;
		rtcp = (janus_rtcp_header *)((uint32_t*)rtcp + length + 1);
	}
	return 0;
}

// clang -g -fsanitize=address,fuzzer jrtcp.c -o jrtcp
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    janus_rtcp_get_remb((char *) data, size);
    return 0;
}
