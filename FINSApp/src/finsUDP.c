/*
	Factory Intelligent Network Service
	
	This is an asyn driver, supporting various asyn interfaces, which acts as both a
	UDP server and client to send requests and receive replies from the Ethernet unit of the PLC.

	Interfaces:
	
		asynOctet
		r	FINS_MODEL
		w	FINS_CYCLE_TIME_RESET
		
		Int32
		r	FINS_DM_READ
		r	FINS_AR_READ
		r	FINS_IO_READ
		r	FINS_DM_READ_32
		r	FINS_AR_READ_32
		r	FINS_IO_READ_32
		r	FINS_CYCLE_TIME_MEAN
		r	FINS_CYCLE_TIME_MAX
		r	FINS_CYCLE_TIME_MIN
		r	FINS_CPU_STATUS
		r	FINS_CPU_MODE
		w	FINS_DM_WRITE
		w	FINS_DM_WRITE_NOREAD
		w	FINS_AR_WRITE
		w	FINS_AR_WRITE_NOREAD
		w	FINS_IO_WRITE
		w	FINS_IO_WRITE_NOREAD
		w	FINS_CYCLE_TIME_RESET
		w	FINS_DM_WRITE_32
		w	FINS_DM_WRITE_32_NOREAD
		w	FINS_AR_WRITE_32
		w	FINS_AR_WRITE_32_NOREAD
		w	FINS_IO_WRITE_32
		w	FINS_IO_WRITE_32_NOREAD
		
		Int16Array
		r	FINS_DM_READ
		r	FINS_AR_READ
		r	FINS_IO_READ
		r	FINS_CLOCK_READ
		w	FINS_DM_WRITE
		w	FINS_AR_WRITE
		w	FINS_IO_WRITE
		
		Int32Array
		r	FINS_DM_READ_32
		r	FINS_AR_READ_32
		r	FINS_IO_READ_32
		r	FINS_CYCLE_TIME
		w	FINS_DM_WRITE_32
		w	FINS_AR_WRITE_32
		w	FINS_IO_WRITE_32
		
		Float32Array
		r	FINS_DM_READ_32
		r	FINS_AR_READ_32
		r	FINS_IO_READ_32
		w	FINS_DM_WRITE_32
		w	FINS_AR_WRITE_32
		w	FINS_IO_WRITE_32
		
	ASYN_CANBLOCK is set because the driver must wait for the reply
	ASYN_MULTIDEVICE is set so that the address field can be used to set the PLC's memory address
	
	The commands supported by this driver are for CPU units. They will probably not work if
	commands are sent directly to a CJ1W-PNT21 PROFINET IO Controller.
	
	We assume that the PLC Ethernet unit receives commands on UDP port 9600. It sends replies to the
	port number we use to send the request.
	
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#ifdef vxWorks
#include <sockLib.h>
#include <inetLib.h>
#endif

#ifdef _WIN32
#include <Ws2tcpip.h>
#endif /* _WIN32 */

#include <cantProceed.h>
#include <epicsMutex.h>
#include <epicsEvent.h>
#include <epicsStdio.h>
#include <epicsString.h>
#include <epicsThread.h>
#include <epicsAssert.h>
#include <epicsTime.h>
#include <asynDriver.h>
#include <asynDrvUser.h>
#include <asynOctet.h>
#include <asynInt32.h>
#include <asynInt16Array.h>
#include <asynInt32Array.h>
#include <asynFloat32Array.h>
#include <iocsh.h>
#include <registryFunction.h>
#include <epicsExport.h>
#include <epicsEndian.h>

#include <osiUnistd.h>
#include <osiSock.h>

/* PLC memory  types */

#define DM	0x82
#define IO	0xB0
#define AR	0xB3
#define CT	0x89

/* offsets into the FINS UDP packet */

#define ICF	0
#define RSV	1
#define GCT	2
#define DNA	3
#define DA1	4
#define DA2	5
#define SNA	6
#define SA1	7
#define SA2	8
#define SID	9

#define MRC	10
#define SRC	11
#define COM	12

#define MRES	12
#define SRES	13

#define RESP	14

#define MIN_RESP_LEN	14

/* constants */

#define FINS_UDP_PORT		9600				/* default PLC FINS port */
#define FINS_TCP_PORT		9600				/* default PLC FINS port */
#define FINS_MAX_WORDS		500
#define FINS_MAX_MSG		((FINS_MAX_WORDS) * 2 + 100)
#define FINS_MAX_HEADER		32
#define FINS_TIMEOUT		1				/* asyn default timeout */
#define FINS_SOURCE_ADDR	0xFE				/* default node address 254 */
#define FINS_GATEWAY		0x02

#define FINS_MODEL_LENGTH	20

/*
	Some byte swapping macros
	
	PLC transmits 16-bit data as high byte - low byte, but when reading 32-bit data as two 16-bit words
	it is transfered as low word - high word. Commands which return 32-bit data use high word - low word.

		IOC			PLC
		00 01 02 03		00 01 02 03
	BE	11 22 33 44		33 44 11 22
	LE	44 33 22 11		33 44 11 22
	
	From PLC
		B8 6E 2F 62 = 2.06201e-10

	On Linux PC
		B8 6E 2F 62 = -5.678775e-05
		6E B8 62 2F =  2.062010e-10
*/

#define BESWAP32(a)	(((a) & 0x0000ffff) << 16) | (((a) & 0xffff0000) >> 16)
#define LESWAP32(a)	(((a) & 0x00ff00ff) <<  8) | (((a) & 0xff00ff00) >>  8)

#if (EPICS_BYTE_ORDER == EPICS_ENDIAN_LITTLE)

	#define BSWAP16(a)	(((a) & 0x00ff) << 8) | (((a) & 0xff00) >> 8)
	#define BSWAP32(a)	(((a) & 0x000000ff) << 24) | (((a) & 0x0000ff00) << 8) | (((a) & 0x00ff0000) >> 8) | (((a) & 0xff000000) >> 24)
	#define SWAPT		"swapping"

	#define WSWAP32 LESWAP32

#else

	#define BSWAP16(a)	(a)
	#define BSWAP32(a)	(a)
	#define SWAPT		"copying"

	#define WSWAP32 BESWAP32
	
#endif

static const char* socket_errmsg()
{
	static char error_message[2048];
	epicsSocketConvertErrnoToString(error_message, sizeof(error_message));
	return error_message;
}

typedef struct drvPvt
{
	epicsMutexId mutexId;

	int connected;
	SOCKET fd;
	int tcp_protocol; // 1 if using tcp(STREAM), 0 if udp(DGRAM)
	
	const char *portName;
	asynInterface common;
	asynInterface drvUser;
	asynInterface octet;
	asynInterface int32;
	asynInterface int16Array;
	asynInterface int32Array;
	asynInterface float32Array;
	void *pasynPvt;			/* For registerInterruptSource */
	
	uint8_t node;

	epicsUInt8 sid;			/* seesion id - increment for each message */
	
	struct sockaddr_in addr;	/* PLC destination address */
	
	epicsFloat32 tMax, tMin, tLast;	/* Max and Min and last response time of PLC */
	
	char reply[FINS_MAX_MSG];
	char message[FINS_MAX_MSG];
	
} drvPvt;

static void flushUDP(const char *func, drvPvt *pdrvPvt, asynUser *pasynUser);
static void FINSerror(drvPvt *pdrvPvt, asynUser *pasynUser, const char *name, const unsigned char mres, const unsigned char sres);

/*** asynCommon methods ***************************************************************************/

static void report(void *drvPvt, FILE *fp, int details);
static asynStatus aconnect(void *drvPvt, asynUser *pasynUser);
static asynStatus adisconnect(void *drvPvt, asynUser *pasynUser);
static asynCommon asyn = { report, aconnect, adisconnect };

/*** asynOctet methods ****************************************************************************/

static asynStatus socketRead (void *drvPvt, asynUser *pasynUser, char *data, size_t maxchars, size_t *nbytesTransfered, int *eomReason);
static asynStatus socketWrite(void *drvPvt, asynUser *pasynUser, const char *data, size_t numchars, size_t *nbytesTransfered);
static asynStatus flushIt (void *drvPvt, asynUser *pasynUser);

/*** asynInt32 methods ****************************************************************************/

static asynStatus WriteInt32(void *drvPvt, asynUser *pasynUser, epicsInt32 value);
static asynStatus ReadInt32(void *drvPvt, asynUser *pasynUser, epicsInt32 *value);

static asynInt32 ifaceInt32 = { WriteInt32, ReadInt32, NULL, NULL, NULL};

/*** asynInt16Array methods ***********************************************************************/

static asynStatus WriteInt16Array(void *drvPvt, asynUser *pasynUser, epicsInt16 *value, size_t nelements);
static asynStatus ReadInt16Array(void *drvPvt, asynUser *pasynUser, epicsInt16 *value, size_t nelements, size_t *nIn);

static asynInt16Array ifaceInt16Array = { WriteInt16Array, ReadInt16Array, NULL, NULL};

/*** asynInt32Array methods ***********************************************************************/

static asynStatus WriteInt32Array(void *drvPvt, asynUser *pasynUser, epicsInt32 *value, size_t nelements);
static asynStatus ReadInt32Array(void *drvPvt, asynUser *pasynUser, epicsInt32 *value, size_t nelements, size_t *nIn);

static asynInt32Array ifaceInt32Array = { WriteInt32Array, ReadInt32Array, NULL, NULL};

/*** asynFloat32Array *****************************************************************************/

static asynStatus WriteFloat32Array(void *drvPvt, asynUser *pasynUser, epicsFloat32 *value, size_t nelements);
static asynStatus ReadFloat32Array(void *drvPvt, asynUser *pasynUser, epicsFloat32 *value, size_t nelements, size_t *nIn);

static asynFloat32Array ifaceFloat32Array = { WriteFloat32Array, ReadFloat32Array, NULL, NULL};

/*** asynDrvUser **********************************************************************************/

asynStatus drvUserCreate (void *drvPvt, asynUser *pasynUser, const char *drvInfo, const char **pptypeName, size_t *psize);
asynStatus drvUserGetType(void *drvPvt, asynUser *pasynUser, const char **pptypeName, size_t *psize);
asynStatus drvUserDestroy(void *drvPvt, asynUser *pasynUser);

static asynDrvUser ifaceDrvUser = { drvUserCreate, NULL, NULL };

/**************************************************************************************************/

enum FINS_COMMANDS
{
	FINS_NULL,
	FINS_DM_READ, FINS_DM_WRITE, FINS_DM_WRITE_NOREAD,
	FINS_IO_READ, FINS_IO_WRITE, FINS_IO_WRITE_NOREAD,
	FINS_AR_READ, FINS_AR_WRITE, FINS_AR_WRITE_NOREAD,
	FINS_CT_READ, FINS_CT_WRITE,
	FINS_DM_READ_32, FINS_DM_WRITE_32, FINS_DM_WRITE_32_NOREAD,
	FINS_IO_READ_32, FINS_IO_WRITE_32, FINS_IO_WRITE_32_NOREAD,
	FINS_AR_READ_32, FINS_AR_WRITE_32, FINS_AR_WRITE_32_NOREAD,
	FINS_CT_READ_32, FINS_CT_WRITE_32, FINS_CT_WRITE_32_NOREAD,
	FINS_READ_MULTI,
	FINS_WRITE_MULTI,
	FINS_SET_MULTI_TYPE,
	FINS_SET_MULTI_ADDR,
	FINS_CLR_MULTI,
	FINS_MODEL,
	FINS_CPU_STATUS,
	FINS_CPU_MODE,
	FINS_CYCLE_TIME_RESET,
	FINS_CYCLE_TIME,
	FINS_CYCLE_TIME_MEAN,
	FINS_CYCLE_TIME_MAX,
	FINS_CYCLE_TIME_MIN,
	FINS_MONITOR,
	FINS_CLOCK_READ,
	FINS_EXPLICIT
};

//extern int errno;

int finsUDPInit(const char *portName, const char *address, const char* protocol)
{
	static const char *FUNCNAME = "finsUDPInit";
	drvPvt *pdrvPvt;
	asynStatus status;
	asynOctet *pasynOctet;
	int fins_port;
	
	pdrvPvt = callocMustSucceed(1, sizeof(drvPvt), FUNCNAME);
	pdrvPvt->portName = epicsStrDup(portName);
	
	if ( (protocol != NULL) && !strcmp(protocol, "TCP") )
	{
		pdrvPvt->tcp_protocol = 1;
		fins_port = FINS_TCP_PORT;
	}
	else // default is UDP
	{
		pdrvPvt->tcp_protocol = 0;
		fins_port = FINS_UDP_PORT;
	}
	
	pasynOctet = callocMustSucceed(1, sizeof(asynOctet), FUNCNAME);
	
/* asynCommon */

	pdrvPvt->common.interfaceType = asynCommonType;
	pdrvPvt->common.pinterface = (void *) &asyn;
	pdrvPvt->common.drvPvt = pdrvPvt;

	status = pasynManager->registerPort(portName, ASYN_MULTIDEVICE | ASYN_CANBLOCK, 1, 0, 0);

	if (status != asynSuccess)
	{
		printf("%s: driver registerPort failed\n", FUNCNAME);
		return (-1);
	}
	
/* common */

	status = pasynManager->registerInterface(portName, &pdrvPvt->common);
	
	if (status != asynSuccess)
	{
		printf("%s: registerInterface common failed\n", FUNCNAME);
		return (-1);
	}

/* drvUser */

	pdrvPvt->drvUser.interfaceType = asynDrvUserType;
	pdrvPvt->drvUser.pinterface = &ifaceDrvUser;
	pdrvPvt->drvUser.drvPvt = pdrvPvt;

	status = pasynManager->registerInterface(portName, &pdrvPvt->drvUser);

	if (status != asynSuccess)
	{
		printf("%s: registerInterface drvUser failed\n", FUNCNAME);
		return 0;
	}
	
/* asynOctet methods */

	pasynOctet->write = socketWrite;
	pasynOctet->read = socketRead;
	pasynOctet->flush = flushIt;

	pdrvPvt->octet.interfaceType = asynOctetType;
	pdrvPvt->octet.pinterface = pasynOctet;
	pdrvPvt->octet.drvPvt = pdrvPvt;

	status = pasynOctetBase->initialize(portName, &pdrvPvt->octet, 0, 0, 0);
	
	if (status == asynSuccess)
	{
		status = pasynManager->registerInterruptSource(portName, &pdrvPvt->octet, &pdrvPvt->pasynPvt);
	}
		
	if (status != asynSuccess)
	{
		printf("%s: registerInterface asynOctet failed\n", FUNCNAME);
		return (-1);
	}

/* asynInt32 */

	pdrvPvt->int32.interfaceType = asynInt32Type;
	pdrvPvt->int32.pinterface = &ifaceInt32;
	pdrvPvt->int32.drvPvt = pdrvPvt;
	
	status = pasynInt32Base->initialize(portName, &pdrvPvt->int32);
	
	if (status == asynSuccess)
	{
		status = pasynManager->registerInterruptSource(portName, &pdrvPvt->int32, &pdrvPvt->pasynPvt);
	}
		
	if (status != asynSuccess)
	{
		printf("%s: registerInterface asynInt32 failed\n", FUNCNAME);
		return (-1);
	}
	
/* asynInt16Array */

	pdrvPvt->int16Array.interfaceType = asynInt16ArrayType;
	pdrvPvt->int16Array.pinterface = &ifaceInt16Array;
	pdrvPvt->int16Array.drvPvt = pdrvPvt;
	
	status = pasynInt16ArrayBase->initialize(portName, &pdrvPvt->int16Array);
	
	if (status == asynSuccess)
	{
		status = pasynManager->registerInterruptSource(portName, &pdrvPvt->int16Array, &pdrvPvt->pasynPvt);
	}
		
	if (status != asynSuccess)
	{
		printf("%s: registerInterface asynInt16Array failed\n", FUNCNAME);
		return (-1);
	}

/* asynInt32Array */

	pdrvPvt->int32Array.interfaceType = asynInt32ArrayType;
	pdrvPvt->int32Array.pinterface = &ifaceInt32Array;
	pdrvPvt->int32Array.drvPvt = pdrvPvt;
	
	status = pasynInt32ArrayBase->initialize(portName, &pdrvPvt->int32Array);
	
	if (status == asynSuccess)
	{
		status = pasynManager->registerInterruptSource(portName, &pdrvPvt->int32Array, &pdrvPvt->pasynPvt);
	}
		
	if (status != asynSuccess)
	{
		printf("%s: registerInterface asynInt32Array failed\n", FUNCNAME);
		return (-1);
	}

/* asynFloat32Array */

	pdrvPvt->float32Array.interfaceType = asynFloat32ArrayType;
	pdrvPvt->float32Array.pinterface = &ifaceFloat32Array;
	pdrvPvt->float32Array.drvPvt = pdrvPvt;
	
	status = pasynFloat32ArrayBase->initialize(portName, &pdrvPvt->float32Array);
	
	if (status == asynSuccess)
	{
		status = pasynManager->registerInterruptSource(portName, &pdrvPvt->float32Array, &pdrvPvt->pasynPvt);
	}
		
	if (status != asynSuccess)
	{
		printf("%s: registerInterface asynFloat32Array failed\n", FUNCNAME);
		return (-1);
	}
	if ( pdrvPvt->tcp_protocol )
	{
		pdrvPvt->fd = epicsSocketCreate(PF_INET, SOCK_STREAM, 0);
	}
	else
	{
		pdrvPvt->fd = epicsSocketCreate(PF_INET, SOCK_DGRAM, 0);
	}
	if (pdrvPvt->fd < 0)
	{
		printf("%s: Can't create socket: %s", FUNCNAME, socket_errmsg());
		return (-1);
	}
	if (aToIPAddr(address, fins_port, &pdrvPvt->addr) < 0)
	{
		printf("Bad IP address %s\n", address);
		return (-1);
	}

	if ( !(pdrvPvt->tcp_protocol) )
	{
	
	/* create incoming FINS UDP server port - dynamically allocated */
	
		struct sockaddr_in addr;
		const int addrlen = sizeof(struct sockaddr_in);
		
		memset(&(addr), 0, addrlen);

		addr.sin_addr.s_addr = htonl(INADDR_ANY);
		addr.sin_family = AF_INET;
		addr.sin_port = htons(0);

		errno = 0;
		
		if (bind(pdrvPvt->fd, (struct sockaddr *) &addr, addrlen) < 0)
		{
			epicsSocketDestroy(pdrvPvt->fd);
			
			printf("%s: bind failed with %s.\n", FUNCNAME, socket_errmsg());
			return (-1);
		}
	}
		
	/* find our port number and inform the user */
	
		{
			struct sockaddr_in name;
#ifdef vxWorks
			int namelen = sizeof(name);
#else
			socklen_t namelen = sizeof(name);
#endif			
			errno = 0;
		
			if (getsockname(pdrvPvt->fd, (struct sockaddr *) &name, &namelen) < 0)
			{
				printf("%s: getsockname failed with %s.\n", FUNCNAME, socket_errmsg());
				
				return (-1);
			}
			
			printf("%s: using port %d\n", FUNCNAME, name.sin_port);
		}
		

	/* node address is last byte of IP address */
		
	pdrvPvt->node = ntohl(pdrvPvt->addr.sin_addr.s_addr) & 0xff;
		
	printf("%s: PLC node %d\n", FUNCNAME, pdrvPvt->node);
	pdrvPvt->tMin = 100.0;
	
 	return (0);
}

static void report(void *pvt, FILE *fp, int details)
{
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	char ip[32];
	
	ipAddrToDottedIP(&pdrvPvt->addr, ip, sizeof(ip));
	
	fprintf(fp, "%s: connected %s \n", pdrvPvt->portName, (pdrvPvt->connected ? "Yes" : "No"));
	fprintf(fp, "    PLC IP: %s  Node: %d\n", ip, pdrvPvt->node);
	fprintf(fp, "    Max: %.4fs  Min: %.4fs  Last: %.4fs\n", pdrvPvt->tMax, pdrvPvt->tMin, pdrvPvt->tLast);
}

static asynStatus aconnect(void *pvt, asynUser *pasynUser)
{
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	asynStatus status;
	int addr;
	
	status = pasynManager->getAddr(pasynUser, &addr);
    
	if (status != asynSuccess) return status;
	
	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s finsUDP:connect addr %d\n", pdrvPvt->portName, addr);
	
	if (addr >= 0)
	{
		pasynManager->exceptionConnect(pasynUser);
		return (asynSuccess);
	}
	
	if (pdrvPvt->connected)
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s finsUDP:connect port already connected\n", pdrvPvt->portName);
		return (asynError);
	}

	if (connect(pdrvPvt->fd, (const struct sockaddr*)&pdrvPvt->addr, sizeof(pdrvPvt->addr)) < 0)
	{
		printf("Bad connection to address %s port %h\n", inet_ntoa(pdrvPvt->addr.sin_addr), ntohs(pdrvPvt->addr.sin_port));
		return (asynError);
	}
	pdrvPvt->connected = 1;
	pasynManager->exceptionConnect(pasynUser);
	return (asynSuccess);
}

static asynStatus adisconnect(void *pvt, asynUser *pasynUser)
{
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	asynStatus status;
	int addr;
	
	status = pasynManager->getAddr(pasynUser, &addr);
    
	if (status != asynSuccess) return status;
	
	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s finsUDP:disconnect addr %d\n", pdrvPvt->portName, addr);

	if (addr >= 0)
	{
		pasynManager->exceptionDisconnect(pasynUser);
		return (asynSuccess);
	}
	
	if (!pdrvPvt->connected)
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s finsUDP:disconnect port not connected\n", pdrvPvt->portName);
		return (asynError);
	}
	if ( pdrvPvt->tcp_protocol )
	{
		shutdown(pdrvPvt->fd, SHUT_RDWR);
		epicsSocketDestroy(pdrvPvt->fd);
		pdrvPvt->fd = epicsSocketCreate(PF_INET, SOCK_STREAM, 0);
	}
	pdrvPvt->connected = 0;
	pasynManager->exceptionDisconnect(pasynUser);
	
	return (asynSuccess);
}

static asynStatus flushIt(void *pvt, asynUser *pasynUser)
{
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	
	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s flush\n", pdrvPvt->portName);

	if (pdrvPvt->fd >= 0)
	{
		flushUDP("flushIt", pdrvPvt, pasynUser);
	}
	
 	return (asynSuccess);
}

/******************************************************************************/

static void flushUDP(const char *func, drvPvt *pdrvPvt, asynUser *pasynUser)
{
	struct sockaddr from_addr;
	int bytes;
	fd_set reply_fds;
	struct timeval no_wait;
#ifdef vxWorks
	int iFromLen = 0;
#else
	socklen_t iFromLen = 0;
#endif		
	do
	{			
// Winsock lacks MSG_DONWAIT so we need to use select() instead, which should work on both Linux and Windows
//		bytes = recvfrom(pdrvPvt->fd, pdrvPvt->reply, FINS_MAX_MSG, MSG_DONTWAIT, &from_addr, &iFromLen);
		FD_ZERO(&reply_fds);
		FD_SET(pdrvPvt->fd, &reply_fds);
		no_wait.tv_sec = no_wait.tv_usec = 0;
		if ( select((int)pdrvPvt->fd + 1, &reply_fds, NULL, NULL, &no_wait) > 0 ) // nfds parameter is ignored on Windows, so cast to avoid warning
		{
			bytes = recvfrom(pdrvPvt->fd, pdrvPvt->reply, FINS_MAX_MSG, 0, &from_addr, &iFromLen);
		}
		else
		{
			bytes = 0;
		}
		if (bytes > 0)
		{
			asynPrint(pasynUser, ASYN_TRACEIO_DRIVER, "%s: port %s, flushed %d bytes.\n", func, pdrvPvt->portName, bytes);
		}
	}
	while (bytes > 0);
}
		
/******************************************************************************/

/*
	Form a FINS read message, send request, wait for the reply and check for errors
	
	This function knows about various message types an forms the correct message
	and processes the reply based on pasynUser->reason.
	
	Document W421 says that the maximum FINS message size is 2012 bytes, which is larger than the MTU.
	We'll limit the maximum number of words to 500 which will be sufficient for all of our current applications.

	data		epicsInt16, epicsInt32 or epicsFloat32 data is written here
	nelements	number of 16 or 32 bit words to read
	address	PLC memory address
	asynSize	sizeof(epicsInt16) for asynInt16Array or sizeof(epicsInt32) for asynInt16Array and asynInt32Array.
*/

static int finsSocketRead(drvPvt *pdrvPvt, asynUser *pasynUser, void *data, const size_t nelements, const epicsUInt16 address, size_t *transfered, size_t asynSize)
{
	static const char *FUNCNAME = "finsSocketRead";
	int recvlen, sendlen = 0;

	epicsTimeStamp ets, ete;

/* initialise header */

	pdrvPvt->message[ICF] = 0x80;
	pdrvPvt->message[RSV] = 0x00;
	pdrvPvt->message[GCT] = FINS_GATEWAY;

	pdrvPvt->message[DNA] = 0x00;
	pdrvPvt->message[DA1] = pdrvPvt->node;
	pdrvPvt->message[DA2] = 0x00;

	pdrvPvt->message[SNA] = 0x00;
	pdrvPvt->message[SA1] = FINS_SOURCE_ADDR;
	pdrvPvt->message[SA2] = 0x00;

	switch (pasynUser->reason)
	{
	
	/* Memory read */
	
		case FINS_DM_READ:
		case FINS_AR_READ:
		case FINS_IO_READ:
		case FINS_DM_WRITE:
		case FINS_AR_WRITE:
		case FINS_IO_WRITE:
		{
			pdrvPvt->message[MRC] = 0x01;
			pdrvPvt->message[SRC] = 0x01;

		/* memory type */

			switch (pasynUser->reason)
			{	
				case FINS_DM_READ:
				case FINS_DM_WRITE:
				{
					pdrvPvt->message[COM] = DM;
					break;
				}
				
				case FINS_AR_READ:
				case FINS_AR_WRITE:
				{
					pdrvPvt->message[COM] = AR;
					break;
				}
				
				case FINS_IO_READ:
				case FINS_IO_WRITE:
				{
					pdrvPvt->message[COM] = IO;
					break;
				}
				
				default:
				{
					asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, bad switch.\n", FUNCNAME, pdrvPvt->portName);
					return (-1);
				}
			}

		/* start address */

			pdrvPvt->message[COM+1] = address >> 8;
			pdrvPvt->message[COM+2] = address & 0xff;
			pdrvPvt->message[COM+3] = 0x00;

		/* length */

			pdrvPvt->message[COM+4] = (char)(nelements >> 8);
			pdrvPvt->message[COM+5] = nelements & 0xff;

			sendlen = COM + 6;
			
			break;
		}

		case FINS_DM_READ_32:
		case FINS_AR_READ_32:
		case FINS_IO_READ_32:
		case FINS_DM_WRITE_32:
		case FINS_AR_WRITE_32:
		case FINS_IO_WRITE_32:
		{
			pdrvPvt->message[MRC] = 0x01;
			pdrvPvt->message[SRC] = 0x01;

		/* memory type */

			switch (pasynUser->reason)
			{	
				case FINS_DM_READ_32:
				case FINS_DM_WRITE_32:
				{
					pdrvPvt->message[COM] = DM;
					break;
				}
				
				case FINS_AR_READ_32:
				case FINS_AR_WRITE_32:
				{
					pdrvPvt->message[COM] = AR;
					break;
				}
				
				case FINS_IO_READ_32:
				case FINS_IO_WRITE_32:
				{
					pdrvPvt->message[COM] = IO;
					break;
				}
				
				default:
				{
					return (-1);
				}
			}

		/* start address */

			pdrvPvt->message[COM+1] = address >> 8;
			pdrvPvt->message[COM+2] = address & 0xff;
			pdrvPvt->message[COM+3] = 0x00;

		/* length */

			pdrvPvt->message[COM+4] = (char)((nelements << 1) >> 8);
			pdrvPvt->message[COM+5] = (nelements << 1) & 0xff;

			sendlen = COM + 6;
			
			break;
		}
		
	/* Multiple memory read */
	
	/*
		Allow the user to configure a number of non-consecutive 16 bit memory locations and types.
		The address parameter is used as an index into the array.
	*/
		case FINS_READ_MULTI:
		{
#if 0
			unsigned char *mm = &pdrvPvt->message[COM];
			
			pdrvPvt->message[MRC] = 0x01;
			pdrvPvt->message[SRC] = 0x04;

			sendlen = COM;
			
			for (n = 0; n < pdrvPvt->mmList[address].length; n++)
			{
				*mm++ = pdrvPvt->mmList[address].type[n];
				*mm++ = pdrvPvt->mmList[address].addr[n] >> 8;
				*mm++ = pdrvPvt->mmList[address].addr[n] & 0xff;
				*mm++ = 0x00;
				
				sendlen += 4;
			}
#endif
			break;
		}
		
		case FINS_MODEL:
		{
			pdrvPvt->message[MRC] = 0x05;
			pdrvPvt->message[SRC] = 0x02;

		/* address is unit number */
		
			pdrvPvt->message[COM + 0] = address & 0xff;
			pdrvPvt->message[COM + 1] = 1;
			
			sendlen = COM + 2;
			
			break;
		}
		
		case FINS_CPU_STATUS:
		case FINS_CPU_MODE:
		{
			pdrvPvt->message[MRC] = 0x06;
			pdrvPvt->message[SRC] = 0x01;
			
			sendlen = COM;

			break;
		}
	
		case FINS_CYCLE_TIME:
		case FINS_CYCLE_TIME_MEAN:
		case FINS_CYCLE_TIME_MAX:
		case FINS_CYCLE_TIME_MIN:
		{
			pdrvPvt->message[MRC] = 0x06;
			pdrvPvt->message[SRC] = 0x20;

			pdrvPvt->message[COM] = 0x01;
			
			sendlen = COM + 1;
			
			break;
		}

		case FINS_CLOCK_READ:
		{
			pdrvPvt->message[MRC] = 0x07;
			pdrvPvt->message[SRC] = 0x01;
			
			sendlen = COM;

			break;
		}
			
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (-1);
		}
	}
	
	pdrvPvt->message[SID] = pdrvPvt->sid++;

/* flush any old data */

	flushUDP("finsSocketRead", pdrvPvt, pasynUser);

	asynPrintIO(pasynUser, ASYN_TRACEIO_DRIVER, pdrvPvt->message, sendlen, "%s: port %s, sending %d bytes.\n", FUNCNAME, pdrvPvt->portName, sendlen);

	epicsTimeGetCurrent(&ets);
	
/* send request */

	errno = 0;
	
	if (send(pdrvPvt->fd, pdrvPvt->message, sendlen, 0) != sendlen)
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, send() failed with %s.\n", FUNCNAME, pdrvPvt->portName, socket_errmsg());
		return (-1);
	}

/* receive reply with timeout */

	{
		fd_set rfds;
		struct timeval tv;
		
		FD_ZERO(&rfds);
		FD_SET(pdrvPvt->fd, &rfds);
		
	/* timeout */

		if (pasynUser->timeout > 0.0)
		{
			tv.tv_sec = (long) pasynUser->timeout;
			tv.tv_usec = 0;
		}
		else
		{
			tv.tv_sec = FINS_TIMEOUT;
			tv.tv_usec = 0;
		}

		errno = 0;
		
		switch (select((int)pdrvPvt->fd + 1, &rfds, NULL, NULL, &tv))  // nfds parameter is ignored on Windows, so cast to avoid warning 
		{
			case -1:
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, select() failed with %s.\n", FUNCNAME, pdrvPvt->portName, socket_errmsg());
	
				return (-1);
				break;
			}
			
			case 0:
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, select() timeout.\n", FUNCNAME, pdrvPvt->portName);

				return (-1);
				break;
			}
			
			default:
			{
				break;
			}
		}
	}

	{
		struct sockaddr from_addr;
#ifdef vxWorks
		int iFromLen = 0;
#else
		socklen_t iFromLen = 0;
#endif
		errno = 0;
		
		if ((recvlen = recvfrom(pdrvPvt->fd, pdrvPvt->reply, FINS_MAX_MSG, 0, &from_addr, &iFromLen)) < 0)
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, recvfrom() with %s.\n", FUNCNAME, pdrvPvt->portName, socket_errmsg());
			return (-1);
		}
	}

	epicsTimeGetCurrent(&ete);
	
	{
		const epicsFloat32 diff = (epicsFloat32)epicsTimeDiffInSeconds(&ete, &ets);
	
		if (diff > pdrvPvt->tMax) pdrvPvt->tMax = diff;
		if (diff < pdrvPvt->tMin) pdrvPvt->tMin = diff;
		
		pdrvPvt->tLast = diff;
	}
	
	asynPrintIO(pasynUser, ASYN_TRACEIO_DRIVER, pdrvPvt->reply, recvlen, "%s: port %s, received %d bytes.\n", FUNCNAME, pdrvPvt->portName, recvlen);

/* Illegal response length check */
	
	if (recvlen < MIN_RESP_LEN)
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, receive length too small.\n", FUNCNAME, pdrvPvt->portName);
		return (-1);
	}
	
	if ((pdrvPvt->message[DNA] != pdrvPvt->reply[SNA]) || (pdrvPvt->message[DA1] != pdrvPvt->reply[SA1]) || (pdrvPvt->message[DA2] != pdrvPvt->reply[SA2]))
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, illegal source address received.\n", FUNCNAME, pdrvPvt->portName);
		return (-1);
	}

/* SID check */
	
	if (pdrvPvt->message[SID] != pdrvPvt->reply[SID])
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, SID %d sent, wrong SID %d received.\n", FUNCNAME, pdrvPvt->portName, pdrvPvt->message[SID], pdrvPvt->reply[SID]);
		return (-1);
	}

/* command check */

	if ((pdrvPvt->reply[MRC] != pdrvPvt->message[MRC]) || (pdrvPvt->reply[SRC] != pdrvPvt->message[SRC]))
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, wrong MRC/SRC received.\n", FUNCNAME, pdrvPvt->portName);
		return (-1);
	}

/* check response code */

	if ((pdrvPvt->reply[MRES] != 0x00) || (pdrvPvt->reply[SRES] != 0x00))
	{
		FINSerror(pdrvPvt, pasynUser, FUNCNAME, pdrvPvt->reply[MRES], pdrvPvt->reply[SRES]);
		return (-1);
	}

/* extract data */

	switch (pasynUser->reason)
	{
		case FINS_DM_READ:
		case FINS_AR_READ:
		case FINS_IO_READ:
		case FINS_DM_WRITE:
		case FINS_AR_WRITE:
		case FINS_IO_WRITE:
		{

		/* asynInt16Array */
		
			if (asynSize == sizeof(epicsUInt16))
			{
				int i;
				epicsUInt16 *ptrs = (epicsUInt16 *) &pdrvPvt->reply[RESP];
				epicsUInt16 *ptrd = (epicsUInt16 *) data;

				for (i = 0; i < nelements; i++)
				{
					ptrd[i] = BSWAP16(ptrs[i]);
				}
					
				asynPrint(pasynUser, ASYN_TRACEIO_DRIVER, "%s: port %s, %s %d 16-bit words.\n", FUNCNAME, pdrvPvt->portName, SWAPT, nelements);
			}
			else
			
		/* asynInt32 * 1 */
		
			{			
				int i;
				epicsUInt16 *ptrs = (epicsUInt16 *) &pdrvPvt->reply[RESP];
				epicsUInt32 *ptrd = (epicsUInt32 *) data;

				for (i = 0; i < nelements; i++)
				{
					ptrd[i] = (epicsUInt32) BSWAP16(ptrs[i]);
				}
					
				asynPrint(pasynUser, ASYN_TRACEIO_DRIVER, "%s: port %s, %s %d 16-bit word.\n", FUNCNAME, pdrvPvt->portName, SWAPT, nelements);
			}
			
		/* check the number of elements received */
		
			if (transfered)
			{
				*transfered = (recvlen - RESP) / sizeof(epicsUInt16);
			}
			
			break;
		}

		case FINS_DM_READ_32:
		case FINS_AR_READ_32:
		case FINS_IO_READ_32:
		case FINS_DM_WRITE_32:
		case FINS_AR_WRITE_32:
		case FINS_IO_WRITE_32:
		{		
			int i;
			epicsUInt32 *ptrs = (epicsUInt32 *) &pdrvPvt->reply[RESP];
			epicsUInt32 *ptrd = (epicsUInt32 *) data;

			for (i = 0; i < nelements; i++)
			{
				ptrd[i] = WSWAP32(ptrs[i]);
			}
				
			asynPrint(pasynUser, ASYN_TRACEIO_DRIVER, "%s: port %s, swapping %d 32-bit words.\n", FUNCNAME, pdrvPvt->portName, nelements);

		/* check the number of elements received */
		
			if (transfered)
			{
				*transfered = (recvlen - RESP) / sizeof(epicsUInt32);
			}
			
			break;
		}
		
/* return a string of 20 chars */

		case FINS_MODEL:
		{
			memcpy(data, &pdrvPvt->reply[RESP + 2], 20);
			
			if (transfered)
			{
				*transfered = FINS_MODEL_LENGTH;
			}
			
			break;
		}

/* return status - epicsInt32 */

		case FINS_CPU_STATUS:
		{
			*(epicsInt32 *)(data) = pdrvPvt->reply[RESP + 0];
			
			if (transfered)
			{
				*transfered = 1;
			}
			
			break;
		}
		
/* return mode - epicsInt32 */

		case FINS_CPU_MODE:
		{
			*(epicsInt32 *)(data) = pdrvPvt->reply[RESP + 1];			

			if (transfered)
			{
				*transfered = 1;
			}
			
			break;
		}

/* return 3 parameters - epicsInt32 */

		case FINS_CYCLE_TIME:
		{
			int i;
			epicsInt32 *rep = (epicsInt32 *) &pdrvPvt->reply[RESP + 0];
			epicsInt32 *dat = (epicsInt32 *) data;

			for (i = 0; i < 3; i++)
			{
				dat[i] = BSWAP32(rep[i]);
			}
				
			if (transfered)
			{
				*transfered = 3;
			}
			
			break;
		}
		
/* return mean - epicsInt32 */

		case FINS_CYCLE_TIME_MEAN:
		{
			const epicsInt32 *rep = (epicsInt32 *) &pdrvPvt->reply[RESP + 0];

			*(epicsInt32 *)(data) = BSWAP32(*rep);

			if (transfered)
			{
				*transfered = 1;
			}
			
			break;
		}
		
/* return max - epicsInt32 */

		case FINS_CYCLE_TIME_MAX:
		{
			const epicsInt32 *rep = (epicsInt32 *) &pdrvPvt->reply[RESP + 4];

			*(epicsInt32 *)(data) = BSWAP32(*rep);

			if (transfered)
			{
				*transfered = 1;
			}
			
			break;
		}
		
/* return min - epicsInt32 */

		case FINS_CYCLE_TIME_MIN:
		{
			const epicsInt32 *rep = (epicsInt32 *) &pdrvPvt->reply[RESP + 8];

			*(epicsInt32 *)(data) = BSWAP32(*rep);

			if (transfered)
			{
				*transfered = 1;
			}
			
			break;
		}

		case FINS_CLOCK_READ:
		{
			epicsInt8  *rep = (epicsInt8 *)  &pdrvPvt->reply[RESP + 0];
			epicsInt16 *dat = (epicsInt16 *) data;
			int i;
				
			for (i = 0; i < 7; i++)
			{
				*dat++ = *rep++;
			}
				
			if (transfered)
			{
				*transfered = 7;
			}
			
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (-1);
		}
	}

	return (0);	
}

/*
	asynSize is either sizeof(epicsInt16) for asynInt16Array or sizeof(epicsInt32) for asynInt16Array and asynInt32Array.
*/
	
static int finsSocketWrite(drvPvt *pdrvPvt, asynUser *pasynUser, const void *data, size_t nwords, const epicsUInt16 address, size_t asynSize)
{
	static const char *FUNCNAME = "finsSocketWrite";
	int recvlen, sendlen;

	epicsTimeStamp ets, ete;
	
/* initialise header */

	pdrvPvt->message[ICF] = 0x80;
	pdrvPvt->message[RSV] = 0x00;
	pdrvPvt->message[GCT] = FINS_GATEWAY;

	pdrvPvt->message[DNA] = 0x00;
	pdrvPvt->message[DA1] = pdrvPvt->node;
	pdrvPvt->message[DA2] = 0x00;

	pdrvPvt->message[SNA] = 0x00;
	pdrvPvt->message[SA1] = FINS_SOURCE_ADDR;
	pdrvPvt->message[SA2] = 0x00;
	
	switch (pasynUser->reason)
	{
	
	/* Memory write */
	
		case FINS_DM_WRITE:
		case FINS_DM_WRITE_NOREAD:
		case FINS_AR_WRITE:
		case FINS_AR_WRITE_NOREAD:
		case FINS_IO_WRITE:
		case FINS_IO_WRITE_NOREAD:
		{
			pdrvPvt->message[MRC] = 0x01;
			pdrvPvt->message[SRC] = 0x02;
				
		/* memory type */

			switch (pasynUser->reason)
			{	
				case FINS_DM_WRITE:
				case FINS_DM_WRITE_NOREAD:
				{
					pdrvPvt->message[COM] = DM;
					break;
				}
				
				case FINS_AR_WRITE:
				case FINS_AR_WRITE_NOREAD:
				{
					pdrvPvt->message[COM] = AR;
					break;
				}
				
				case FINS_IO_WRITE:
				case FINS_IO_WRITE_NOREAD:
				{
					pdrvPvt->message[COM] = IO;
					break;
				}
				
				default:
				{
					asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, bad switch.\n", FUNCNAME, pdrvPvt->portName);
					return (-1);
				}
			}
			
		/* start address */

			pdrvPvt->message[COM+1] = address >> 8;
			pdrvPvt->message[COM+2] = address & 0xff;
			pdrvPvt->message[COM+3] = 0x00;

		/* length */

			pdrvPvt->message[COM+4] = (char)(nwords >> 8);
			pdrvPvt->message[COM+5] = nwords & 0xff;

		/* asynInt16Array */
		
			if (asynSize == sizeof(epicsUInt16))
			{
				int i;
				epicsUInt16 *ptrd = (epicsUInt16 *) &pdrvPvt->message[COM + 6];
				epicsUInt16 *ptrs = (epicsUInt16 *) data;

				for (i = 0; i < nwords; i++)
				{
					ptrd[i] = BSWAP16(ptrs[i]);
				}

				asynPrint(pasynUser, ASYN_TRACEIO_DRIVER, "%s: port %s, %s %d 16-bit words.\n", FUNCNAME, pdrvPvt->portName, SWAPT, nwords);
			}
			else
			
		/* asynInt32 * 1 */
		
			{
				int i;
				epicsUInt16 *ptrd = (epicsUInt16 *) &pdrvPvt->message[COM + 6];
				epicsUInt32 *ptrs = (epicsUInt32 *) data;

				for (i = 0; i < nwords; i++)
				{
					ptrd[i] = BSWAP16((epicsUInt16) ptrs[i]);
				}

				asynPrint(pasynUser, ASYN_TRACEIO_DRIVER, "%s: port %s, %s %d 16-bit word.\n", FUNCNAME, pdrvPvt->portName, SWAPT, nwords);				
			}
			
			sendlen = (int)(COM + 6 + nwords * sizeof(short));
			
			break;
		}

		case FINS_DM_WRITE_32:
		case FINS_DM_WRITE_32_NOREAD:
		case FINS_AR_WRITE_32:
		case FINS_AR_WRITE_32_NOREAD:
		case FINS_IO_WRITE_32:
		case FINS_IO_WRITE_32_NOREAD:
		{
			pdrvPvt->message[MRC] = 0x01;
			pdrvPvt->message[SRC] = 0x02;
				
		/* memory type */

			switch (pasynUser->reason)
			{	
				case FINS_DM_WRITE_32:
				case FINS_DM_WRITE_32_NOREAD:
				{
					pdrvPvt->message[COM] = DM;
					break;
				}
				
				case FINS_AR_WRITE_32:
				case FINS_AR_WRITE_32_NOREAD:
				{
					pdrvPvt->message[COM] = AR;
					break;
				}
				
				case FINS_IO_WRITE_32:
				case FINS_IO_WRITE_32_NOREAD:
				{
					pdrvPvt->message[COM] = IO;
					break;
				}
				
				default:
				{
					return (-1);
				}
			}
			
		/* start address */

			pdrvPvt->message[COM+1] = address >> 8;
			pdrvPvt->message[COM+2] = address & 0xff;
			pdrvPvt->message[COM+3] = 0x00;

		/* length */

			pdrvPvt->message[COM+4] = (char)(nwords >> 8);
			pdrvPvt->message[COM+5] = nwords & 0xff;

		/* convert data  */

			{
				int i;
				epicsUInt32 *ptrd = (epicsUInt32 *) &pdrvPvt->message[COM + 6];
				epicsUInt32 *ptrs = (epicsUInt32 *) data;
				
				for (i = 0; i < nwords / 2; i++)
				{
					ptrd[i] = WSWAP32(ptrs[i]);
				}
				
				asynPrint(pasynUser, ASYN_TRACEIO_DRIVER, "%s: port %s, swapping %d 32-bit words.\n", FUNCNAME, pdrvPvt->portName, nwords >> 1);
			}

			sendlen = (int)(COM + 6 + nwords * sizeof(short));
			
			break;
		}

	/* cycle time reset */
	
		case FINS_CYCLE_TIME_RESET:
		{
			pdrvPvt->message[MRC] = 0x06;
			pdrvPvt->message[SRC] = 0x20;
			pdrvPvt->message[COM] = 0x00;
			
			sendlen = COM + 1;

			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (-1);
		}
	}
		
	pdrvPvt->message[SID] = pdrvPvt->sid++;

/* flush any old data */

	flushUDP("finsSocketWrite", pdrvPvt, pasynUser);
	
	asynPrintIO(pasynUser, ASYN_TRACEIO_DRIVER, pdrvPvt->message, sendlen, "%s: port %s, sending %d bytes.\n", FUNCNAME, pdrvPvt->portName, sendlen);
	
	epicsTimeGetCurrent(&ets);
	
/* send request */

	errno = 0;
	
	if (send(pdrvPvt->fd, pdrvPvt->message, sendlen, 0) != sendlen)
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, send() failed with %s.\n", FUNCNAME, pdrvPvt->portName, socket_errmsg());
		return (-1);
	}

/* receive reply with timeout */

	{
		fd_set rfds;
		struct timeval tv;
		
		FD_ZERO(&rfds);
		FD_SET(pdrvPvt->fd, &rfds);
		
	/* timeout */

		if (pasynUser->timeout > 0.0)
		{
			tv.tv_sec = (long) pasynUser->timeout;
			tv.tv_usec = 0;
		}
		else
		{
			tv.tv_sec = FINS_TIMEOUT;
			tv.tv_usec = 0;
		}
		
		errno = 0;
		
		switch (select((int)pdrvPvt->fd + 1, &rfds, NULL, NULL, &tv)) // nfds parameter is ignored on Windows, so cast to avoid warning
		{
			case -1:
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, select() failed with %s.\n", FUNCNAME, pdrvPvt->portName, socket_errmsg());

				return (-1);
				break;
			}
			
			case 0:
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, select() timeout.\n", FUNCNAME, pdrvPvt->portName);
				
				return (-1);
				break;
			}
			
			default:
			{
				break;
			}
		}
	}

	{
		struct sockaddr from_addr;
#ifdef vxWorks
		int iFromLen = 0;
#else
		socklen_t iFromLen = 0;
#endif
		if ((recvlen = recvfrom(pdrvPvt->fd, pdrvPvt->reply, FINS_MAX_MSG, 0, &from_addr, &iFromLen)) < 0)
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, recvfrom() error.\n", FUNCNAME, pdrvPvt->portName);
			return (-1);
		}
	}

	epicsTimeGetCurrent(&ete);

	{
		const epicsFloat32 diff = (epicsFloat32)epicsTimeDiffInSeconds(&ete, &ets);
	
		if (diff > pdrvPvt->tMax) pdrvPvt->tMax = diff;
		if (diff < pdrvPvt->tMin) pdrvPvt->tMin = diff;
		
		pdrvPvt->tLast = diff;
	}
	
	asynPrintIO(pasynUser, ASYN_TRACEIO_DRIVER, pdrvPvt->reply, recvlen, "%s: port %s, received %d bytes.\n", FUNCNAME, pdrvPvt->portName, recvlen);

/* Illegal response length check */
	
	if (recvlen < MIN_RESP_LEN)
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, receive length too small.\n", FUNCNAME, pdrvPvt->portName);
		return (-1);
	}
	
	if ((pdrvPvt->message[DNA] != pdrvPvt->reply[SNA]) || (pdrvPvt->message[DA1] != pdrvPvt->reply[SA1]) || (pdrvPvt->message[DA2] != pdrvPvt->reply[SA2]))
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, illegal source address received.\n", FUNCNAME, pdrvPvt->portName);
		return (-1);
	}

/* SID check */
	
	if (pdrvPvt->message[SID] != pdrvPvt->reply[SID])
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, wrong SID received.\n", FUNCNAME, pdrvPvt->portName);
		return (-1);
	}

/* command check */

	if ((pdrvPvt->reply[MRC] != pdrvPvt->message[MRC]) || (pdrvPvt->reply[SRC] != pdrvPvt->message[SRC]))
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, wrong MRC/SRC received.\n", FUNCNAME, pdrvPvt->portName);
		return (-1);
	}

/* check response code */

	if ((pdrvPvt->reply[MRES] != 0x00) || (pdrvPvt->reply[SRES] != 0x00))
	{
		FINSerror(pdrvPvt, pasynUser, FUNCNAME, pdrvPvt->reply[MRES], pdrvPvt->reply[SRES]);
		return (-1);
	}

	return (0);
}

/*** asynOctet ************************************************************************************/

/*

	We use asynOctet to read character strings.
	We could also use it for EXPLICIT MESSAGE SEND (0x28 0x01) commands
*/

static asynStatus socketRead(void *pvt, asynUser *pasynUser, char *data, size_t maxchars, size_t *nbytesTransfered, int *eomReason)
{
	static const char *FUNCNAME = "socketRead";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	char *type = NULL;
	
	*eomReason = 0;
	*nbytesTransfered = 0;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}
	
/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_MODEL:
		{
			type = "FINS_MODEL";
			
			if (maxchars < FINS_MODEL_LENGTH)
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, length is not >= %d for FINS_MODEL\n", FUNCNAME, pdrvPvt->portName, addr, FINS_MODEL_LENGTH);
				return (asynError);
			}
			
			break;
		}
		
	/* no more reasons for asynOctetRead */
	
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, %s\n", FUNCNAME, pdrvPvt->portName, addr, type);

/* send FINS request */

	if (finsSocketRead(pdrvPvt, pasynUser, (void *) data, maxchars, addr, nbytesTransfered, 0) < 0)
	{
		return (asynError);
	}
	
	if (eomReason)
	{
		*eomReason |= ASYN_EOM_END;
	}

	asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "%s: port %s, addr %d, read %d bytes.\n", FUNCNAME, pdrvPvt->portName, addr, *nbytesTransfered);

   	return (asynSuccess);
}

/*
	Form a FINS write message, send request, wait for the reply and check for errors

	Parameters required:
	
		IP address	Set during initialisation
		command type	read, write, cpu status, cycle time etc. Set by pasynUser->reason
		memory type	DM, IO, AR, CT. Set by pasynUser->reason
		start address	Set by asyn address
		data length	Determined by record type
		
		asyn("FINS0", 0xffff, 1) FINS_MODEL, FINS_CYCLE_TIME_RESET, ...
		
	nwords is only used for memory access operations like DM, AR, IO arrays of DM, AR, IO 16/32 access 
*/

static asynStatus socketWrite(void *pvt, asynUser *pasynUser, const char *data, size_t numchars, size_t *nbytesTransfered)
{
	static const char *FUNCNAME = "socketWrite";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	char *type = NULL;
	
	*nbytesTransfered = 0;

	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}
	
/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_CYCLE_TIME_RESET:
		{
			type = "FINS_CYCLE_TIME_RESET";
			
			break;			/* numchars is not used because the message has a fixed size */
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, %s\n", FUNCNAME, pdrvPvt->portName, addr, type);
	
/* form FINS message and send data */
	
	if (finsSocketWrite(pdrvPvt, pasynUser, (void *) data, numchars, addr, 0) < 0)
	{
		return (asynError);
	}

/* assume for now that we can always write the full request */

	*nbytesTransfered = numchars;

	asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "%s: port %s, addr %d, wrote %d bytes.\n", FUNCNAME, pdrvPvt->portName, addr, numchars);

   	return (asynSuccess);
}

/*** asynInt32 ************************************************************************************/

static asynStatus ReadInt32(void *pvt, asynUser *pasynUser, epicsInt32 *value)
{
	static const char *FUNCNAME = "ReadInt32";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_READ:
		{
			type = "FINS_DM_READ";
			break;
		}
		
		case FINS_AR_READ:
		{
			type = "FINS_AR_READ";
			break;
		}
		
		case FINS_IO_READ:
		{
			type = "FINS_IO_READ";
			break;
		}
		
		case FINS_DM_READ_32:
		{
			type = "FINS_DM_READ_32";
			break;
		}
		
		case FINS_AR_READ_32:
		{
			type = "FINS_AR_READ_32";
			break;
		}
		
		case FINS_IO_READ_32:
		{
			type = "FINS_IO_READ_32";
			break;
		}
		
		case FINS_CYCLE_TIME_MEAN:
		{
			type = "FINS_CYCLE_TIME_MEAN";
			break;
		}
		
		case FINS_CYCLE_TIME_MAX:
		{
			type = "FINS_CYCLE_TIME_MAX";
			break;
		}
		
		case FINS_CYCLE_TIME_MIN:
		{
			type = "FINS_CYCLE_TIME_MIN";
			break;
		}
		
		case FINS_CPU_STATUS:
		{
			type = "FINS_CPU_STATUS";
			break;
		}
		
		case FINS_CPU_MODE:
		{
			type = "FINS_CPU_MODE";
			break;
		}

	/* this gets called at initialisation by write methods */
	
		case FINS_DM_WRITE:
		case FINS_IO_WRITE:
		case FINS_AR_WRITE:
		case FINS_CT_WRITE:
		case FINS_DM_WRITE_32:
		case FINS_IO_WRITE_32:
		case FINS_AR_WRITE_32:
		case FINS_CT_WRITE_32:
		{
			type = "WRITE";
			break;
		}

		case FINS_DM_WRITE_NOREAD:
		case FINS_IO_WRITE_NOREAD:
		case FINS_AR_WRITE_NOREAD:
		case FINS_DM_WRITE_32_NOREAD:
		case FINS_IO_WRITE_32_NOREAD:
		case FINS_AR_WRITE_32_NOREAD:
		{
			asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, WRITE_NOREAD\n", FUNCNAME, pdrvPvt->portName, addr);
			return (asynError);
		}

		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, no such command %d.\n", FUNCNAME, pdrvPvt->portName, addr, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, %s\n", FUNCNAME, pdrvPvt->portName, addr, type);

/* send FINS request */

	if (finsSocketRead(pdrvPvt, pasynUser, (void *) value, 1, addr, NULL, sizeof(epicsUInt32)) < 0)
	{
		return (asynError);
	}

	asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "%s: port %s, addr %d, read 1 word.\n", FUNCNAME, pdrvPvt->portName, addr);

	return (asynSuccess);
}

static asynStatus WriteInt32(void *pvt, asynUser *pasynUser, epicsInt32 value)
{
	static const char *FUNCNAME = "WriteInt32";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE:
		{
			type = "FINS_DM_WRITE";
			break;
		}

		case FINS_DM_WRITE_NOREAD:
		{
			type = "FINS_DM_WRITE_NOREAD";
			break;
		}
		
		case FINS_AR_WRITE:
		{
			type = "FINS_AR_WRITE";
			break;
		}

		case FINS_AR_WRITE_NOREAD:
		{
			type = "FINS_AR_WRITE_NOREAD";
			break;
		}
		
		case FINS_IO_WRITE:
		{
			type = "FINS_IO_WRITE";
			break;
		}
		
		case FINS_IO_WRITE_NOREAD:
		{
			type = "FINS_IO_WRITE_NOREAD";
			break;
		}

		case FINS_CYCLE_TIME_RESET:
		{
			type = "FINS_CYCLE_TIME_RESET";
			break;
		}

		case FINS_DM_WRITE_32:
		{
			type = "FINS_DM_WRITE_32";
			break;
		}

		case FINS_DM_WRITE_32_NOREAD:
		{
			type = "FINS_DM_WRITE_32_NOREAD";
			break;
		}
		
		case FINS_AR_WRITE_32:
		{
			type = "FINS_AR_WRITE_32";
			break;
		}
		
		case FINS_AR_WRITE_32_NOREAD:
		{
			type = "FINS_AR_WRITE_32_NOREAD";
			break;
		}
		
		case FINS_IO_WRITE_32:
		{
			type = "FINS_IO_WRITE_32";
			break;
		}
		
		case FINS_IO_WRITE_32_NOREAD:
		{
			type = "FINS_IO_WRITE_32_NOREAD";
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, %s\n", FUNCNAME, pdrvPvt->portName, addr, type);
	
	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE:
		case FINS_DM_WRITE_NOREAD:
		case FINS_AR_WRITE:
		case FINS_AR_WRITE_NOREAD:
		case FINS_IO_WRITE:
		case FINS_IO_WRITE_NOREAD:
		case FINS_CYCLE_TIME_RESET:
		{
			
		/* form FINS message and send data */

			if (finsSocketWrite(pdrvPvt, pasynUser, (void *) &value, sizeof(epicsInt16) / sizeof(epicsInt16), addr, sizeof(epicsUInt32)) < 0)
			{
				return (asynError);
			}
			
			break;
		}

		case FINS_DM_WRITE_32:
		case FINS_DM_WRITE_32_NOREAD:
		case FINS_AR_WRITE_32:
		case FINS_AR_WRITE_32_NOREAD:
		case FINS_IO_WRITE_32:
		case FINS_IO_WRITE_32_NOREAD:
		{
			
		/* form FINS message and send data */

			if (finsSocketWrite(pdrvPvt, pasynUser, (void *) &value, sizeof(epicsInt32) / sizeof(epicsInt16), addr, sizeof(epicsUInt32)) < 0)
			{
				return (asynError);
			}
			
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "%s: port %s, addr %d, wrote 1 word.\n", FUNCNAME, pdrvPvt->portName, addr);

	return (asynSuccess);
}

/*** asynInt16Array *******************************************************************************/

static asynStatus ReadInt16Array(void *pvt, asynUser *pasynUser, epicsInt16 *value, size_t nelements, size_t *nIn)
{
	static const char *FUNCNAME = "ReadInt16Array";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_READ:
		{
			type = "FINS_DM_READ";
			break;
		}
		
		case FINS_AR_READ:
		{
			type = "FINS_AR_READ";
			break;
		}
		case FINS_IO_READ:
		{
			type = "FINS_IO_READ";
			break;
		}
		
		case FINS_CLOCK_READ:
		{
			type = "FINS_CLOCK_READ";
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, %s\n", FUNCNAME, pdrvPvt->portName, addr, type);

	switch (pasynUser->reason)
	{
		case FINS_DM_READ:
		case FINS_AR_READ:
		case FINS_IO_READ:
		{
			if (nelements > FINS_MAX_WORDS)
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, request too big.\n", FUNCNAME, pdrvPvt->portName, addr);
				return (asynError);
			}
			
			break;
		}
		
		case FINS_CLOCK_READ:
		{
			if (nelements != 7)
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, FINS_CLOCK_READ size != 7.\n", FUNCNAME, pdrvPvt->portName, addr);
				return (asynError);
			}
			
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}
		
/* send FINS request */

	if (finsSocketRead(pdrvPvt, pasynUser, (char *) value, nelements, addr, nIn, sizeof(epicsUInt16)) < 0)
	{
		*nIn = 0;
		return (asynError);
	}

	asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "%s: port %s, addr %d, read %d 16-bit words.\n", FUNCNAME, pdrvPvt->portName, addr, *nIn);

	return (asynSuccess);
}

static asynStatus WriteInt16Array(void *pvt, asynUser *pasynUser, epicsInt16 *value, size_t nelements)
{
	static const char *FUNCNAME = "WriteInt16Array";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE:
		{
			type = "FINS_DM_WRITE";
			break;
		}
		
		case FINS_AR_WRITE:
		{
			type = "FINS_AR_WRITE";
			break;
		}
		case FINS_IO_WRITE:
		{
			type = "FINS_IO_WRITE";
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, %s\n", FUNCNAME, pdrvPvt->portName, addr, type);

	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE:
		case FINS_AR_WRITE:
		case FINS_IO_WRITE:
		{
			if (nelements > FINS_MAX_WORDS)
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, request too big.\n", FUNCNAME, pdrvPvt->portName, addr);
				return (asynError);
			}
			
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}
	
/* form FINS message and send data */

	if (finsSocketWrite(pdrvPvt, pasynUser, (void *) value, nelements * sizeof(epicsInt16) / sizeof(epicsInt16), addr, sizeof(epicsUInt16)) < 0)
	{
		return (asynError);
	}

	asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "%s: port %s, addr %d, wrote %d 16-bit words.\n", FUNCNAME, pdrvPvt->portName, addr, nelements);

	return (asynSuccess);
}

/*** asynInt32Array *******************************************************************************/

static asynStatus ReadInt32Array(void *pvt, asynUser *pasynUser, epicsInt32 *value, size_t nelements, size_t *nIn)
{
	static const char *FUNCNAME = "ReadInt32Array";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_READ_32:
		{
			type = "FINS_DM_READ_32";
			break;
		}
		
		case FINS_AR_READ_32:
		{
			type = "FINS_AR_READ_32";
			break;
		}
		
		case FINS_IO_READ_32:
		{
			type = "FINS_IO_READ_32";
			break;
		}
		
		case FINS_CYCLE_TIME:
		{
			type = "FINS_CYCLE_TIME";
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, %s\n", FUNCNAME, pdrvPvt->portName, addr, type);

	switch (pasynUser->reason)
	{
		case FINS_DM_READ_32:
		case FINS_AR_READ_32:
		case FINS_IO_READ_32:
		{
			if ((nelements * 2) > FINS_MAX_WORDS)
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, request too big\n", FUNCNAME, pdrvPvt->portName, addr);
				return (asynError);
			}
			
			break;
		}

		case FINS_CYCLE_TIME:
		{
			if (nelements != 3)
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, request %d too small.\n", FUNCNAME, pdrvPvt->portName, addr, nelements);
				return (asynError);
			}
			
			break;
		}

		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}

/* send FINS request */

	if (finsSocketRead(pdrvPvt, pasynUser, (void *) value, nelements, addr, nIn, sizeof(epicsUInt32)) < 0)
	{
		*nIn = 0;
		return (asynError);
	}

	asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "%s: port %s, addr %d, read %d 32-bit words.\n", FUNCNAME, pdrvPvt->portName, addr, *nIn);
	
	return (asynSuccess);
}

static asynStatus WriteInt32Array(void *pvt, asynUser *pasynUser, epicsInt32 *value, size_t nelements)
{
	static const char *FUNCNAME = "WriteInt32Array";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE_32:
		{
			type = "FINS_DM_WRITE_32";
			break;
		}
		
		case FINS_AR_WRITE_32:
		{
			type = "FINS_AR_WRITE_32";
			break;
		}
		
		case FINS_IO_WRITE_32:
		{
			type = "FINS_IO_WRITE_32";
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, %s\n", FUNCNAME, pdrvPvt->portName, addr, type);

	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE_32:
		case FINS_AR_WRITE_32:
		case FINS_IO_WRITE_32:
		{
			if ((nelements * 2) > FINS_MAX_WORDS)
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, request too big.\n", FUNCNAME, pdrvPvt->portName, addr);
				return (asynError);
			}
			
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}
	
/* form FINS message and send data */

	if (finsSocketWrite(pdrvPvt, pasynUser, (void *) value, nelements * sizeof(epicsInt32) / sizeof(epicsInt16), addr, sizeof(epicsUInt32)) < 0)
	{
		return (asynError);
	}

	asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "%s: port %s, addr %d, wrote %d 32-bit words.\n", FUNCNAME, pdrvPvt->portName, addr, nelements);

	return (asynSuccess);
}

/*** asynFloat32Array *****************************************************************************/

/*
	Read 32 bit values from the PLC which are encoded as IEEE floats
*/

static asynStatus ReadFloat32Array(void *pvt, asynUser *pasynUser, epicsFloat32 *value, size_t nelements, size_t *nIn)
{
	static const char *FUNCNAME = "ReadFloat32Array";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_READ_32:
		{
			type = "FINS_DM_READ_32";
			break;
		}
		
		case FINS_AR_READ_32:
		{
			type = "FINS_AR_READ_32";
			break;
		}
		
		case FINS_IO_READ_32:
		{
			type = "FINS_IO_READ_32";
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, %s\n", FUNCNAME, pdrvPvt->portName, addr, type);

	switch (pasynUser->reason)
	{
		case FINS_DM_READ_32:
		case FINS_AR_READ_32:
		case FINS_IO_READ_32:
		{
			if ((nelements * 2) > FINS_MAX_WORDS)
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, request too big.\n", FUNCNAME, pdrvPvt->portName, addr);
				return (asynError);
			}
			
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}
	
/* send FINS request */

	if (finsSocketRead(pdrvPvt, pasynUser, (void *) value, nelements, addr, nIn, sizeof(epicsInt32)) < 0)
	{
		*nIn = 0;
		return (asynError);
	}

	asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "%s: port %s, addr %d, read %d floats.\n", FUNCNAME, pdrvPvt->portName, addr, *nIn);
	
	return (asynSuccess);
}

static asynStatus WriteFloat32Array(void *pvt, asynUser *pasynUser, epicsFloat32 *value, size_t nelements)
{
	static const char *FUNCNAME = "WriteFloat32Array";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE_32:
		{
			type = "FINS_DM_WRITE_32";
			break;
		}
		
		case FINS_AR_WRITE_32:
		{
			type = "FINS_AR_WRITE_32";
			break;
		}
		
		case FINS_IO_WRITE_32:
		{
			type = "FINS_IO_WRITE_32";
			break;
		}

		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, %s\n", FUNCNAME, pdrvPvt->portName, addr, type);

	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE_32:
		case FINS_AR_WRITE_32:
		case FINS_IO_WRITE_32:
		{
			if ((nelements * 2) > FINS_MAX_WORDS)
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, request too big.\n", FUNCNAME, pdrvPvt->portName, addr);
				return (asynError);
			}
			
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, no such command %d.\n", FUNCNAME, pdrvPvt->portName, pasynUser->reason);
			return (asynError);
		}
	}
	
/* form FINS message and send data */

	if (finsSocketWrite(pdrvPvt, pasynUser, (void *) value, nelements * sizeof(epicsFloat32) / sizeof(epicsInt16), addr, sizeof(epicsInt32)) < 0)
	{
		return (asynError);
	}

	asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "%s: port %s, addr %d, wrote %d floats.\n", FUNCNAME, pdrvPvt->portName, addr, nelements);

	return (asynSuccess);
}

/*** asynDrvUser **********************************************************************************/

asynStatus drvUserCreate(void *pvt, asynUser *pasynUser, const char *drvInfo, const char **pptypeName, size_t *psize)
{
	drvPvt *pdrvPvt = (drvPvt *) pvt;

	if (drvInfo)
	{
		if (strcmp("FINS_DM_READ", drvInfo) == 0)
		{
			pasynUser->reason = FINS_DM_READ;
		}
		else
		if (strcmp("FINS_DM_READ_32", drvInfo) == 0)
		{
			pasynUser->reason = FINS_DM_READ_32;
		}
		else
		if (strcmp("FINS_DM_WRITE", drvInfo) == 0)
		{
			pasynUser->reason = FINS_DM_WRITE;
		}
		else
		if (strcmp("FINS_DM_WRITE_NOREAD", drvInfo) == 0)
		{
			pasynUser->reason = FINS_DM_WRITE_NOREAD;
		}
		else
		if (strcmp("FINS_DM_WRITE_32", drvInfo) == 0)
		{
			pasynUser->reason = FINS_DM_WRITE_32;
		}
		else
		if (strcmp("FINS_DM_WRITE_32_NOREAD", drvInfo) == 0)
		{
			pasynUser->reason = FINS_DM_WRITE_32_NOREAD;
		}
		else
		if (strcmp("FINS_IO_READ", drvInfo) == 0)
		{
			pasynUser->reason = FINS_IO_READ;
		}
		else
		if (strcmp("FINS_IO_READ_32", drvInfo) == 0)
		{
			pasynUser->reason = FINS_IO_READ_32;
		}
		else
		if (strcmp("FINS_IO_WRITE", drvInfo) == 0)
		{
			pasynUser->reason = FINS_IO_WRITE;
		}
		else
		if (strcmp("FINS_IO_WRITE_NOREAD", drvInfo) == 0)
		{
			pasynUser->reason = FINS_IO_WRITE_NOREAD;
		}
		else
		if (strcmp("FINS_IO_WRITE_32", drvInfo) == 0)
		{
			pasynUser->reason = FINS_IO_WRITE_32;
		}
		else
		if (strcmp("FINS_IO_WRITE_32_NOREAD", drvInfo) == 0)
		{
			pasynUser->reason = FINS_IO_WRITE_32_NOREAD;
		}
		else
		if (strcmp("FINS_AR_READ", drvInfo) == 0)
		{
			pasynUser->reason = FINS_AR_READ;
		}
		else
		if (strcmp("FINS_AR_READ_32", drvInfo) == 0)
		{
			pasynUser->reason = FINS_AR_READ_32;
		}
		else
		if (strcmp("FINS_AR_WRITE", drvInfo) == 0)
		{
			pasynUser->reason = FINS_AR_WRITE;
		}
		else
		if (strcmp("FINS_AR_WRITE_NOREAD", drvInfo) == 0)
		{
			pasynUser->reason = FINS_AR_WRITE_NOREAD;
		}
		else
		if (strcmp("FINS_AR_WRITE_32", drvInfo) == 0)
		{
			pasynUser->reason = FINS_AR_WRITE_32;
		}
		else
		if (strcmp("FINS_AR_WRITE_32_NOREAD", drvInfo) == 0)
		{
			pasynUser->reason = FINS_AR_WRITE_32_NOREAD;
		}
		else
		if (strcmp("FINS_CT_READ", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CT_READ;
		}
		else
		if (strcmp("FINS_CT_WRITE", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CT_WRITE;
		}
		else
		if (strcmp("FINS_CPU_STATUS", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CPU_STATUS;
		}
		else
		if (strcmp("FINS_CPU_MODE", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CPU_MODE;
		}
		else
		if (strcmp("FINS_MODEL", drvInfo) == 0)
		{
			pasynUser->reason = FINS_MODEL;
		}
		else
		if (strcmp("FINS_CYCLE_TIME_RESET", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CYCLE_TIME_RESET;
		}
		else
		if (strcmp("FINS_CYCLE_TIME", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CYCLE_TIME;
		}
		else
		if (strcmp("FINS_CYCLE_TIME_MEAN", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CYCLE_TIME_MEAN;
		}
		else
		if (strcmp("FINS_CYCLE_TIME_MAX", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CYCLE_TIME_MAX;
		}
		else
		if (strcmp("FINS_CYCLE_TIME_MIN", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CYCLE_TIME_MIN;
		}
		else
		if (strcmp("FINS_MONITOR", drvInfo) == 0)
		{
			pasynUser->reason = FINS_MONITOR;
		}
		else
		if (strcmp("FINS_CLOCK_READ", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CLOCK_READ;
		}
		else
		if (strcmp("FINS_EXPLICIT", drvInfo) == 0)
		{
			pasynUser->reason = FINS_EXPLICIT;
		}
		else
		{
			pasynUser->reason = FINS_NULL;
		}

		asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "drvUserCreate: port %s, %s = %d\n", pdrvPvt->portName, drvInfo, pasynUser->reason);

		return (asynSuccess);
	}

	return (asynError);
}

static const char *error01 = "Local node error";
static const char *error02 = "Destination node error";
static const char *error03 = "Communications controller error";
static const char *error04 = "Not executable";
static const char *error05 = "Routing error";
static const char *error10 = "Command format error";
static const char *error11 = "Parameter error";
static const char *error20 = "Read not possible";
static const char *error21 = "Write not possible";
static const char *error22 = "Not executable in curent mode";
static const char *error23 = "No unit";
static const char *error24 = "Start/Stop not possible";
static const char *error25 = "Unit error";
static const char *error26 = "Command error";
static const char *error30 = "Access rights error";
static const char *error40 = "Abort error";

static void FINSerror(drvPvt *pdrvPvt, asynUser *pasynUser, const char *name, const unsigned char mres, const unsigned char sres)
{
	if (mres & 0x80)
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, Relay Error Flag\n", name, pdrvPvt->portName);
		
		FINSerror(pdrvPvt, pasynUser, name, mres ^ 0x80, sres);
	}
	
	switch (mres)
	{
		case 0x01:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error01, sres);
			break;
		}
		
		case 0x02:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error02, sres);
			break;
		}
		
		case 0x03:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error03, sres);
			break;
		}
		
		case 0x04:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error04, sres);
			break;
		}
		
		case 0x05:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error05, sres);
			break;
		}
		
		case 0x10:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error10, sres);
			break;
		}
		
		case 0x11:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error11, sres);
			break;
		}
		
		case 0x20:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error20, sres);
			break;
		}
		
		case 0x21:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error21, sres);
			break;
		}
		
		case 0x22:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error22, sres);
			break;
		}
		
		case 0x23:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error23, sres);
			break;
		}
		
		case 0x24:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %se 0x%02x\n", name, pdrvPvt->portName, error24, sres);
			break;
		}
		
		case 0x25:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error25, sres);
			break;
		}
		
		case 0x26:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error26, sres);
			break;
		}
		
		case 0x30:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error30, sres);
			break;
		}
		
		case 0x40:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, %s 0x%02x\n", name, pdrvPvt->portName, error40, sres);
			break;
		}
		
		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, Error 0x%02x/0x%02x\n", name, pdrvPvt->portName, mres, sres);
			break;
		}
	}
}

static const iocshArg finsUDPInitArg0 = { "portName", iocshArgString };
static const iocshArg finsUDPInitArg1 = { "IP address", iocshArgString };
static const iocshArg finsUDPInitArg2 = { "protocol", iocshArgString }; // TCP or UDP

static const iocshArg *finsUDPInitArgs[] = { &finsUDPInitArg0, &finsUDPInitArg1, &finsUDPInitArg2 };
static const iocshFuncDef finsUDPInitFuncDef = { "finsUDPInit", 3, finsUDPInitArgs};

static void finsUDPInitCallFunc(const iocshArgBuf *args)
{
	finsUDPInit(args[0].sval, args[1].sval, args[2].sval);
}

static void finsUDPRegister(void)
{
	static int firstTime = 1;
	
	if (firstTime)
	{
		firstTime = 0;
		iocshRegister(&finsUDPInitFuncDef, finsUDPInitCallFunc);
	}
}

epicsExportRegistrar(finsUDPRegister);

/**************************************************************************************************/

/*
	This is a test function to send a FINS data memory read request for two words from
	address 100 to the specified IP address. It will print the data received as hex, or
	a helpful error message if something fails.
*/

int finsTest(char *address)
{
	SOCKET fd;
	struct sockaddr_in addr;
	const int addrlen = sizeof(struct sockaddr_in);
	uint8_t node;
	unsigned char *message;
	int recvlen, sendlen = 0;
	
	message = (unsigned char *) callocMustSucceed(1, FINS_MAX_MSG, "finsTest");
	
/* open a datagram socket */

	fd = epicsSocketCreate(PF_INET, SOCK_DGRAM, 0);
	
	if (fd < 0)
	{
		perror("finsTest: socket");
		return (-1);
	}
	
	memset(&(addr), 0, addrlen);

/* ask for a free port for incoming UDP packets */

	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(0);

/* bind socket to address */

	if (bind(fd, (struct sockaddr *) &addr, addrlen) < 0)
	{
		perror("finsTest: bind failed");
		
		epicsSocketDestroy(fd);
		return (-1);
	}

/* find our port number */
	
	{
		struct sockaddr_in name;
#ifdef vxWorks
		int namelen;
#else
		socklen_t namelen;
#endif			
		getsockname(fd, (struct sockaddr *) &name, &namelen);

		printf("finsTest: port %d bound\n", name.sin_port);
	}
	
/* destination port address used later in sendto() */

	memset(&addr, 0, addrlen);

/*
	addr.sin_family = AF_INET;
	addr.sin_port = htons(FINS_UDP_PORT);
*/

/* convert IP address */

	if (aToIPAddr(address, FINS_UDP_PORT, &addr) < 0)
	{
		epicsSocketDestroy(fd);
		printf("finsTest: Bad IP address %s\n", address);
		return (-1);
	}

/* node address is last byte of IP address */
		
	node = ntohl(addr.sin_addr.s_addr) & 0xff;
		
	printf("PLC node %d\n", node);

/* send a simple FINS command */

	message[ICF] = 0x80;
	message[RSV] = 0x00;
	message[GCT] = 0x02;

	message[DNA] = 0x00;
	message[DA1] = node;		/* destination node */
	message[DA2] = 0x00;

	message[SNA] = 0x00;
	message[SA1] = 0x01;		/* source node */
	message[SA2] = 0x00;

	message[MRC] = 0x01;
	message[SRC] = 0x01;
	message[COM] = DM;		/* data memory read */

	message[COM+1] = 100 >> 8;
	message[COM+2] = 100 & 0xff;
	message[COM+3] = 0x00;		/* start address */

	message[COM+4] = 2 >> 8;
	message[COM+5] = 2 & 0xff;	/* length */

	sendlen = COM + 6;

/* send request */

	if (sendto(fd, message, sendlen, 0, (struct sockaddr *) &addr, addrlen) != sendlen)
	{
		perror("finsTest: sendto");
		epicsSocketDestroy(fd);
		return (-1);
	}

/* receive reply with timeout */

	{
		fd_set rfds;
		struct timeval tv;
		
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		
	/* timeout */

		tv.tv_sec = FINS_TIMEOUT;
		tv.tv_usec = 0;

		switch (select((int)fd + 1, &rfds, NULL, NULL, &tv)) // nfds parameter is ignored on Windows, so cast to avoid warning
		{
			case -1:
			{
				perror("finsTest: select");
	
				return (-1);
				break;
			}
			
			case 0:
			{
				perror("finsTest: select");

				return (-1);
				break;
			}

			default:
			{
				break;
			}
		}
	}

	{
		struct sockaddr from_addr;
#ifdef vxWorks
		int iFromLen = 0;
#else
		socklen_t iFromLen = 0;
#endif
		if ((recvlen = recvfrom(fd, message, FINS_MAX_MSG, 0, &from_addr, &iFromLen)) < 0)
		{
			perror("finsTest: recvfrom");
			epicsSocketDestroy(fd);
			return (-1);
		}
	}

	{
		int i;
		
		for (i = 0; i < recvlen; i++)
		{
			printf("0x%02x ", message[i]);
		}
	
		puts("");
	}

/* Illegal response length check */
	
	if (recvlen < MIN_RESP_LEN)
	{
		puts("finsTest: receive length too small.");
	}

/* check response code */

	if ((message[MRES] != 0x00) || (message[SRES] != 0x00))
	{
		if (message[MRES] & 0x80)
		{
			puts("finsTest: Relay Error Flag set");
			
			message[MRES] ^= 0x80;
		}
		
		switch (message[MRES])
		{
			case 0x01:
			{
				printf("%s 0x%02x\n", error01, message[SRES]);
				break;
			}
		
			case 0x02:
			{
				printf("%s 0x%02x\n", error02, message[SRES]);
				break;
			}
		
			case 0x03:
			{
				printf("%s 0x%02x\n", error03, message[SRES]);
				break;
			}
		
			case 0x04:
			{
				printf("%s 0x%02x\n", error04, message[SRES]);
				break;
			}
		
			case 0x05:
			{
				printf("%s 0x%02x\n", error05, message[SRES]);
				break;
			}
		
			case 0x10:
			{
				printf("%s 0x%02x\n", error10, message[SRES]);
				break;
			}
		
			case 0x11:
			{
				printf("%s 0x%02x\n", error11, message[SRES]);
				break;
			}
		
			case 0x20:
			{
				printf("%s 0x%02x\n", error20, message[SRES]);
				break;
			}
		
			case 0x21:
			{
				printf("%s 0x%02x\n", error21, message[SRES]);
				break;
			}
		
			case 0x22:
			{
				printf("%s 0x%02x\n", error22, message[SRES]);
				break;
			}
		
			case 0x23:
			{
				printf("%s 0x%02x\n", error23, message[SRES]);
				break;
			}
		
			case 0x24:
			{
				printf("%s 0x%02x\n", error24, message[SRES]);
				break;
			}
		
			case 0x25:
			{
				printf("%s 0x%02x\n", error25, message[SRES]);
				break;
			}
		
			case 0x26:
			{
				printf("%s 0x%02x\n", error26, message[SRES]);
				break;
			}
		
			case 0x30:
			{
				printf("%s 0x%02x\n", error30, message[SRES]);
				break;
			}
		
			case 0x40:
			{
				printf("%s 0x%02x\n", error40, message[SRES]);
				break;
			}
		
			default:
			{
				printf("Error 0x%02x/0x%02x\n", message[MRES], message[SRES]);
				break;
			}
		}
	}
		
	epicsSocketDestroy(fd);
	
	return (0);
}

static const iocshArg finsTestArg0 = { "IP address", iocshArgString };

static const iocshArg *finsTestArgs[] = { &finsTestArg0};
static const iocshFuncDef finsTestFuncDef = { "finsTest", 1, finsTestArgs};

static void finsTestCallFunc(const iocshArgBuf *args)
{
	finsTest(args[0].sval);
}

static void finsTestRegister(void)
{
	static int firstTime = 1;
	
	if (firstTime)
	{
		firstTime = 0;
		iocshRegister(&finsTestFuncDef, finsTestCallFunc);
	}
}

epicsExportRegistrar(finsTestRegister);

/**************************************************************************************************/
