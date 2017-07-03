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
		r	FINS_WR_READ
		r	FINS_IO_READ
		r	FINS_DM_READ_32
		r	FINS_AR_READ_32
		r	FINS_WR_READ_32
		r	FINS_IO_READ_32
		r	FINS_CYCLE_TIME_MEAN
		r	FINS_CYCLE_TIME_MAX
		r	FINS_CYCLE_TIME_MIN
		r	FINS_CPU_STATUS
		r	FINS_CPU_MODE
		w	FINS_DM_WRITE
		w	FINS_DM_WRITE_NOREAD
		w	FINS_AR_WRITE
		w	FINS_WR_WRITE
		w	FINS_AR_WRITE_NOREAD
		w	FINS_WR_WRITE_NOREAD
		w	FINS_IO_WRITE
		w	FINS_IO_WRITE_NOREAD
		w	FINS_CYCLE_TIME_RESET
		w	FINS_DM_WRITE_32
		w	FINS_DM_WRITE_32_NOREAD
		w	FINS_AR_WRITE_32
		w	FINS_AR_WRITE_32_NOREAD
		w	FINS_WR_WRITE_32
		w	FINS_WR_WRITE_32_NOREAD
		w	FINS_IO_WRITE_32
		w	FINS_IO_WRITE_32_NOREAD
		
		Int16Array
		r	FINS_DM_READ
		r	FINS_AR_READ
		r	FINS_IO_READ
		r	FINS_CLOCK_READ
		r	FINS_STATUS
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
#include <asynFloat64.h>
#include <asynInt16Array.h>
#include <asynInt32Array.h>
#include <asynFloat32Array.h>
#include <iocsh.h>
#include <registryFunction.h>
#include <epicsExport.h>
#include <epicsEndian.h>
#include <errlog.h>

#include <osiUnistd.h>
#include <osiSock.h>

/* PLC memory  types */
/* note: the bit version of these are 0x80 lower, we shift these using "address_shift" if needed */
#define DM	0x82 /* DM area, word */
#define IO	0xB0 /* CIO area, word */
#define WR  0xB1 /* Work area, word */
#define HR  0xB2 /* Holding area, word */
#define AR	0xB3 /* Auxiliary area, word */
#define CT	0x89 /* CNT, counter area, word */  
#define TM  0x89 /* TIM, timer area, word */

/* offsets into the FINS UDP packet */

/* command format */
#define ICF	0 /* dipslay frame information */
#define RSV	1 /* reserved by system */
#define GCT	2 /* Permissible number fo gateways */
#define DNA	3 /* Destination network address */
#define DA1	4 /* destination node address */
#define DA2	5 /* destination unit address */
#define SNA	6 /* Source network address */
#define SA1	7 /* Source node address */
#define SA2	8 /* Source unit address */
#define SID	9 /* Service ID */
#define MRC	10 /* Main request code */
#define SRC	11 /* Sub request code */
#define COM	12 /* command  + parameters */

/* response format */
#define MRES	12 /* mauin response code */
#define SRES	13 /* sub response code */
#define RESP	14 /* response data */

#define MIN_RESP_LEN	14

/* constants */

#define FINS_UDP_PORT		9600				/* default PLC FINS port */
#define FINS_TCP_PORT		9600				/* default PLC FINS port */
#define FINS_MAX_WORDS		500
#define FINS_MAX_MSG		((FINS_MAX_WORDS) * 2 + 100)
#define FINS_MAX_HEADER		32
#define FINS_TIMEOUT		1				/* asyn default timeout */
#define FINS_SOURCE_ADDR	0xFE			/* default node address 254, used for udp - with tcp we can obtain this another way */
#define FINS_GATEWAY		0x02           /* permissible number of gateways */

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

/* convert a Binary Coded Decimal byte (such as returned by CLOCK_READ) into an integer */
static int bcd2int(unsigned char bcd_byte)
{
    return 10 * (bcd_byte >> 4) + (bcd_byte & 0xf);
}

static const char* socket_errmsg()
{
	static char error_message[2048];
	epicsSocketConvertErrnoToString(error_message, sizeof(error_message));
	return error_message;
}

typedef struct finsTCPHeader
{
	uint32_t header; /* always 0x46494E53 ("FINS" in ASCII) */
	uint32_t length; 
	uint32_t command; 
	uint32_t error_code;
	uint32_t extra[2];
} finsTCPHeader;

typedef struct drvPvt
{
	epicsMutexId mutexId;

	int connected;
	SOCKET fd;
	int tcp_protocol; /* 1 if using tcp(SOCK_STREAM), 0 if udp(SOCK_DGRAM) */
	
	const char *portName;
	asynInterface common;
	asynInterface drvUser;
	asynInterface octet;
	asynInterface int32;
	asynInterface float64;
	asynInterface int16Array;
	asynInterface int32Array;
	asynInterface float32Array;
	void *pasynPvt;			/* For registerInterruptSource */
	
	uint8_t node;
	uint8_t client_node;

	epicsUInt8 sid;			/* seesion id - increment for each message */
	
	uint8_t sna; /* value to use for sna, dna - 0x0 if local, > 0x0 if remote */
	uint8_t dna; /* value to use for sna, dna - 0x0 if local, > 0x0 if remote */
	
	struct sockaddr_in addr;	/* PLC destination address */
	
	epicsFloat32 tMax, tMin, tLast;	/* Max and Min and last response time of PLC */
	
	char reply[FINS_MAX_MSG];
	char message[FINS_MAX_MSG];
	
} drvPvt;

static void flushUDP(const char *func, drvPvt *pdrvPvt, asynUser *pasynUser);
static void FINSerror(drvPvt *pdrvPvt, asynUser *pasynUser, const char *name, unsigned char mres, 
                      unsigned char sres, const char* resp);

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

static asynStatus ReadFloat64(void *drvPvt, asynUser *pasynUser, epicsFloat64 *value);

static asynFloat64 ifaceFloat64 = { NULL, ReadFloat64, NULL, NULL };

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

static int socket_recv(SOCKET fd, char* buffer, int maxlen, int wait_for_all);


static void init_fins_header(finsTCPHeader* fins_header);
static void	byteswap_fins_header(finsTCPHeader* fins_header);
static int send_fins_header(finsTCPHeader* fins_header, SOCKET fd, const char* portName, asynUser* pasynUser, int sendlen, int first_header);
static int recv_fins_header(finsTCPHeader* fins_header, SOCKET fd, const char* portName, asynUser* pasynUser, int first_header);
static const char* finsTCPError(int code);

/**************************************************************************************************/

/* we also support a _Bn suffix to some codes to indicate a bit rather than word operation */ 
enum FINS_COMMANDS
{
	FINS_NULL=0,
	FINS_DM_READ, FINS_DM_WRITE, FINS_DM_WRITE_NOREAD,
	FINS_IO_READ, FINS_IO_WRITE, FINS_IO_WRITE_NOREAD,
	FINS_AR_READ, FINS_AR_WRITE, FINS_AR_WRITE_NOREAD,
	FINS_WR_READ, FINS_WR_WRITE, FINS_WR_WRITE_NOREAD,
	FINS_HR_READ, FINS_HR_WRITE, FINS_HR_WRITE_NOREAD,
	FINS_CT_READ, FINS_CT_WRITE,
	FINS_TM_READ, FINS_TM_WRITE,
	FINS_DM_READ_32, FINS_DM_WRITE_32, FINS_DM_WRITE_32_NOREAD,
	FINS_IO_READ_32, FINS_IO_WRITE_32, FINS_IO_WRITE_32_NOREAD,
	FINS_AR_READ_32, FINS_AR_WRITE_32, FINS_AR_WRITE_32_NOREAD,
	FINS_WR_READ_32, FINS_WR_WRITE_32, FINS_WR_WRITE_32_NOREAD,
	FINS_HR_READ_32, FINS_HR_WRITE_32, FINS_HR_WRITE_32_NOREAD,
	FINS_READ_MULTI,
	FINS_WRITE_MULTI,
	FINS_SET_MULTI_TYPE,
	FINS_SET_MULTI_ADDR,
	FINS_CLR_MULTI,
	FINS_MODEL,
    FINS_STATUS,
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

static const char* FINS_COMMANDS_STR[] =
{
	"FINS_NULL",
	"FINS_DM_READ", "FINS_DM_WRITE", "FINS_DM_WRITE_NOREAD",
	"FINS_IO_READ", "FINS_IO_WRITE", "FINS_IO_WRITE_NOREAD",
	"FINS_AR_READ", "FINS_AR_WRITE", "FINS_AR_WRITE_NOREAD",
	"FINS_WR_READ", "FINS_WR_WRITE", "FINS_WR_WRITE_NOREAD",
	"FINS_HR_READ", "FINS_HR_WRITE", "FINS_HR_WRITE_NOREAD",
	"FINS_CT_READ", "FINS_CT_WRITE",
	"FINS_TM_READ", "FINS_TM_WRITE",
	"FINS_DM_READ_32", "FINS_DM_WRITE_32", "FINS_DM_WRITE_32_NOREAD",
	"FINS_IO_READ_32", "FINS_IO_WRITE_32", "FINS_IO_WRITE_32_NOREAD",
	"FINS_AR_READ_32", "FINS_AR_WRITE_32", "FINS_AR_WRITE_32_NOREAD",
	"FINS_WR_READ_32", "FINS_WR_WRITE_32", "FINS_WR_WRITE_32_NOREAD",
	"FINS_HR_READ_32", "FINS_HR_WRITE_32", "FINS_HR_WRITE_32_NOREAD",
	"FINS_READ_MULTI",
	"FINS_WRITE_MULTI",
	"FINS_SET_MULTI_TYPE",
	"FINS_SET_MULTI_ADDR",
	"FINS_CLR_MULTI",
	"FINS_MODEL",
    "FINS_STATUS",
	"FINS_CPU_STATUS",
	"FINS_CPU_MODE",
	"FINS_CYCLE_TIME_RESET",
	"FINS_CYCLE_TIME",
	"FINS_CYCLE_TIME_MEAN",
	"FINS_CYCLE_TIME_MAX",
	"FINS_CYCLE_TIME_MIN",
	"FINS_MONITOR",
	"FINS_CLOCK_READ",
	"FINS_EXPLICIT"
};

int finsUDPInit(const char *portName, const char *address, const char* protocol)
{
	static const char *FUNCNAME = "finsUDPInit";
	drvPvt *pdrvPvt;
	asynStatus status;
	asynOctet *pasynOctet;
	int fins_port;
	
	pdrvPvt = callocMustSucceed(1, sizeof(drvPvt), FUNCNAME);
	pdrvPvt->portName = epicsStrDup(portName);
	pdrvPvt->connected = 0;
    pdrvPvt->fd = -1;
	if ( (protocol != NULL) && !epicsStrCaseCmp(protocol, "TCP") )
	{
		pdrvPvt->tcp_protocol = 1;
		fins_port = FINS_TCP_PORT;
	}
	else /* default is UDP */
	{
		pdrvPvt->tcp_protocol = 0;
		fins_port = FINS_UDP_PORT;
	}
	
	pasynOctet = callocMustSucceed(1, sizeof(asynOctet), FUNCNAME);
	

	status = pasynManager->registerPort(portName, ASYN_MULTIDEVICE | ASYN_CANBLOCK, 1, 0, 0);

	if (status != asynSuccess)
	{
		errlogPrintf("%s: driver registerPort failed\n", FUNCNAME);
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
		errlogPrintf("%s: Can't create socket: %s", FUNCNAME, socket_errmsg());
		return (-1);
	}
	if (aToIPAddr(address, fins_port, &pdrvPvt->addr) < 0)
	{
		errlogPrintf("%s: Bad IP address %s\n", FUNCNAME, address);
		epicsSocketDestroy(pdrvPvt->fd);
		return (-1);
	}

	errlogSevPrintf(errlogInfo, "%s: using address %s protocol %s\n", FUNCNAME, address, (pdrvPvt->tcp_protocol ? "TCP" : "UDP") );
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
			errlogPrintf("%s: bind failed with %s.\n", FUNCNAME, socket_errmsg());
			epicsSocketDestroy(pdrvPvt->fd);
			return (-1);
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
				errlogPrintf("%s: getsockname failed with %s.\n", FUNCNAME, socket_errmsg());
				epicsSocketDestroy(pdrvPvt->fd);
				return (-1);
			}
			
			errlogSevPrintf(errlogInfo, "%s: using port %d\n", FUNCNAME, name.sin_port);
		}
	}
		
	/* node address is last byte of IP address */
		
	pdrvPvt->node = ntohl(pdrvPvt->addr.sin_addr.s_addr) & 0xff;
			
	errlogSevPrintf(errlogInfo, "%s: PLC node %d\n", FUNCNAME, pdrvPvt->node);
	pdrvPvt->tMin = 100.0;

/* asynCommon */

	pdrvPvt->common.interfaceType = asynCommonType;
	pdrvPvt->common.pinterface = (void *) &asyn;
	pdrvPvt->common.drvPvt = pdrvPvt;
   /* common */

	status = pasynManager->registerInterface(portName, &pdrvPvt->common);
	
	if (status != asynSuccess)
	{
		errlogPrintf("%s: registerInterface common failed\n", FUNCNAME);
		return (-1);
	}

/* drvUser */

	pdrvPvt->drvUser.interfaceType = asynDrvUserType;
	pdrvPvt->drvUser.pinterface = &ifaceDrvUser;
	pdrvPvt->drvUser.drvPvt = pdrvPvt;

	status = pasynManager->registerInterface(portName, &pdrvPvt->drvUser);

	if (status != asynSuccess)
	{
		errlogPrintf("%s: registerInterface drvUser failed\n", FUNCNAME);
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
		errlogPrintf("%s: registerInterface asynOctet failed\n", FUNCNAME);
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
		errlogPrintf("%s: registerInterface asynInt32 failed\n", FUNCNAME);
		return (-1);
	}
	
/* asynFloat64 */

	pdrvPvt->float64.interfaceType = asynFloat64Type;
	pdrvPvt->float64.pinterface = &ifaceFloat64;
	pdrvPvt->float64.drvPvt = pdrvPvt;
	
	status = pasynFloat64Base->initialize(portName, &pdrvPvt->float64);
	
	if (status == asynSuccess)
	{
		status = pasynManager->registerInterruptSource(portName, &pdrvPvt->float64, &pdrvPvt->pasynPvt);
	}
		
	if (status != asynSuccess)
	{
		errlogPrintf("%s: registerInterface asynFloat64 failed\n", FUNCNAME);
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
		errlogPrintf("%s: registerInterface asynInt16Array failed\n", FUNCNAME);
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
		errlogPrintf("%s: registerInterface asynInt32Array failed\n", FUNCNAME);
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
		errlogPrintf("%s: registerInterface asynFloat32Array failed\n", FUNCNAME);
		return (-1);
	}
	
	
 	return (0);
}

static void report(void *pvt, FILE *fp, int details)
{
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	char ip[32];
	
	ipAddrToDottedIP(&pdrvPvt->addr, ip, sizeof(ip));
	
	fprintf(fp, "%s: connected %s protocol %s\n", pdrvPvt->portName, (pdrvPvt->connected ? "Yes" : "No"), (pdrvPvt->tcp_protocol ? "TCP" : "UDP") );
	fprintf(fp, "    PLC IP: %s  Node (DA1): %d Port: %hu\n", ip, pdrvPvt->node, ntohs(pdrvPvt->addr.sin_port));
	fprintf(fp, "    Max: %.4fs  Min: %.4fs  Last: %.4fs\n", pdrvPvt->tMax, pdrvPvt->tMin, pdrvPvt->tLast);
	fprintf(fp, "    client node (SA1): %d SNA: %d DNA: %d Gateway count: %d\n", pdrvPvt->client_node, pdrvPvt->sna, pdrvPvt->dna, FINS_GATEWAY);
}

/* report an error to various places, just to make sure it is received */
static void report_error(asynUser *pasynUser, const char* format, ... )
{
	va_list ap;
	char errmsg[256];
	va_start(ap, format);
	epicsVsnprintf(errmsg, sizeof(errmsg), format, ap);
	asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s", errmsg);
	epicsSnprintf(pasynUser->errorMessage, pasynUser->errorMessageSize, "%s", errmsg); 
	errlogSevPrintf(errlogMajor, "%s", errmsg);
	va_end(ap);
}

static asynStatus aconnect(void *pvt, asynUser *pasynUser)
{
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	asynStatus status;
	int addr;
	finsTCPHeader fins_header;
	
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
//		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s finsUDP:connect port already connected\n", pdrvPvt->portName);
		report_error(pasynUser, "%s finsUDP:connect port already connected\n", pdrvPvt->portName);
		return (asynError);
	}

	if (connect(pdrvPvt->fd, (const struct sockaddr*)&pdrvPvt->addr, sizeof(pdrvPvt->addr)) < 0)
	{
	    report_error(pasynUser, "port %s, connect() to %s port %hu with %s.\n", 
				pdrvPvt->portName, inet_ntoa(pdrvPvt->addr.sin_addr), ntohs(pdrvPvt->addr.sin_port), socket_errmsg());
		return (asynError);
	}
	
	if (pdrvPvt->tcp_protocol)
	{
		if (send_fins_header(&fins_header, pdrvPvt->fd, pdrvPvt->portName, pasynUser, 4, 1) < 0)
		{
		    report_error(pasynUser, "port %s send_fins_header failed", pdrvPvt->portName);
			return (asynError);
		}
		if (recv_fins_header(&fins_header, pdrvPvt->fd, pdrvPvt->portName, pasynUser, 1) < 0)
		{
		    report_error(pasynUser, "port %s recv_fins_header failed", pdrvPvt->portName);
			return (asynError);
		}
		pdrvPvt->client_node = fins_header.extra[0];
        if (pdrvPvt->node != fins_header.extra[1])
        {
            errlogSevPrintf(errlogMajor, "%s finsUDP: response PLC node %d not same as previously configured value %d\n", pdrvPvt->portName, fins_header.extra[1], pdrvPvt->node);
            // should we do      pdrvPvt->node = fins_header.extra[1];     ???         
        }
	}
	else
	{
		pdrvPvt->client_node = FINS_SOURCE_ADDR;
	}
    errlogSevPrintf(errlogInfo, "%s finsUDP: connect client node %d server node %d\n", pdrvPvt->portName, pdrvPvt->client_node, pdrvPvt->node);
    if (1) /* at the moment assume local */
    {
	    pdrvPvt->sna = 0x00; /* local */
	    pdrvPvt->dna = 0x00; /* local */
    }
    else
    {
	    pdrvPvt->sna = 0x01; /* needs to be agreed with PLC */
	    pdrvPvt->dna = 0x02; /* needs to be agreed with PLC */
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
	    /* TODO: send a fins shutdown packet */
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
	int bytes;
	fd_set reply_fds;
	struct timeval no_wait;
	do
	{			
/* Winsock lacks MSG_DONWAIT so we need to use select() instead, which should work on both Linux and Windows
 *		bytes = recvfrom(pdrvPvt->fd, pdrvPvt->reply, FINS_MAX_MSG, MSG_DONTWAIT, &from_addr, &iFromLen); 
 */
		FD_ZERO(&reply_fds);
		FD_SET(pdrvPvt->fd, &reply_fds);
		no_wait.tv_sec = no_wait.tv_usec = 0;
		if ( select((int)pdrvPvt->fd + 1, &reply_fds, NULL, NULL, &no_wait) > 0 ) // nfds parameter is ignored on Windows, so cast to avoid warning
		{
			bytes = socket_recv(pdrvPvt->fd, pdrvPvt->reply, FINS_MAX_MSG, 0);
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
	nelements	number of 8, 16 or 32 bit words to read
	address	PLC memory address
	asynSize	sizeof(epicsInt16) for asynInt16Array or sizeof(epicsInt32) for asynInt16Array and asynInt32Array.
*/

static int finsSocketRead(drvPvt *pdrvPvt, asynUser *pasynUser, void *data, const size_t nelements, epicsUInt16 address, size_t *transfered, size_t asynSize)
{
	static const char *FUNCNAME = "finsSocketRead";
	int recvlen, sendlen = 0;
	unsigned expectedlen;
    finsTCPHeader fins_header;
	epicsTimeStamp ets, ete;
    /* if user_data != 0x0 then we perform a bit rather than word operation */
    unsigned user_data = 0x0, address_shift = 0x0, bit_number = 0x0;
    memcpy(&user_data, &(pasynUser->userData), sizeof(user_data));
    address_shift = (user_data >> 8);
    bit_number = (user_data & 0xff);
    
/* initialise header */

	pdrvPvt->message[ICF] = 0x80;
	pdrvPvt->message[RSV] = 0x00;
	pdrvPvt->message[GCT] = FINS_GATEWAY;

	pdrvPvt->message[DNA] = pdrvPvt->dna;
	pdrvPvt->message[DA1] = pdrvPvt->node;
	pdrvPvt->message[DA2] = 0x00;

	pdrvPvt->message[SNA] = pdrvPvt->sna;
	pdrvPvt->message[SA1] = pdrvPvt->client_node;
	pdrvPvt->message[SA2] = 0x00;

	switch (pasynUser->reason)
	{
	
	/* Memory read */
	
		case FINS_DM_READ:
		case FINS_AR_READ:
		case FINS_WR_READ:
		case FINS_IO_READ:
		case FINS_DM_WRITE:
		case FINS_AR_WRITE:
		case FINS_WR_WRITE:
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
					pdrvPvt->message[COM] = DM - address_shift;
					break;
				}
				
				case FINS_AR_READ:
				case FINS_AR_WRITE:
				{
					pdrvPvt->message[COM] = AR - address_shift;
					break;
				}
				
				case FINS_WR_READ:
				case FINS_WR_WRITE:
				{
					pdrvPvt->message[COM] = WR - address_shift;
					break;
				}

				case FINS_IO_READ:
				case FINS_IO_WRITE:
				{
					pdrvPvt->message[COM] = IO - address_shift;
					break;
				}
				
				case FINS_HR_READ:
				case FINS_HR_WRITE:
				{
					pdrvPvt->message[COM] = HR - address_shift;
					break;
				}

				case FINS_CT_READ:
				case FINS_CT_WRITE:
				{
					pdrvPvt->message[COM] = CT - address_shift;
                    address |= 0x8000;
                    bit_number = 0; /* completion flag */
					break;
				}

				case FINS_TM_READ:
				case FINS_TM_WRITE:
				{
					pdrvPvt->message[COM] = TM - address_shift;
                    bit_number = 0;  /* completion flag */
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
			pdrvPvt->message[COM+3] = bit_number;

		/* length */

			pdrvPvt->message[COM+4] = (char)(nelements >> 8);
			pdrvPvt->message[COM+5] = nelements & 0xff;

			sendlen = COM + 6;
			
			break;
		}

		case FINS_DM_READ_32:
		case FINS_AR_READ_32:
		case FINS_WR_READ_32:
		case FINS_IO_READ_32:
		case FINS_HR_READ_32:
		case FINS_DM_WRITE_32:
		case FINS_AR_WRITE_32:
		case FINS_WR_WRITE_32:
		case FINS_IO_WRITE_32:
		case FINS_HR_WRITE_32:
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
				
				case FINS_WR_READ_32:
				case FINS_WR_WRITE_32:
				{
					pdrvPvt->message[COM] = WR;
					break;
				}

				case FINS_IO_READ_32:
				case FINS_IO_WRITE_32:
				{
					pdrvPvt->message[COM] = IO;
					break;
				}

				case FINS_HR_READ_32:
				case FINS_HR_WRITE_32:
				{
					pdrvPvt->message[COM] = HR;
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
		case FINS_STATUS:
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
	
	if ( pdrvPvt->tcp_protocol && (send_fins_header(&fins_header, pdrvPvt->fd, pdrvPvt->portName, pasynUser, sendlen, 0) < 0) )
	{
		return (-1);
	}
	
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

		errno = 0;		
		if ( pdrvPvt->tcp_protocol && (recv_fins_header(&fins_header, pdrvPvt->fd, pdrvPvt->portName, pasynUser, 0) < 0) )
		{
		    return (-1);
		}
		if ((recvlen = socket_recv(pdrvPvt->fd, pdrvPvt->reply, FINS_MAX_MSG, 0)) < 0)
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, recvfrom() with %s.\n", FUNCNAME, pdrvPvt->portName, socket_errmsg());
			return (-1);
		}
		expectedlen = fins_header.length - 8;
		if ( pdrvPvt->tcp_protocol && (recvlen != expectedlen) )
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, recvfrom() incorrect size %d != %d.\n", FUNCNAME, pdrvPvt->portName, recvlen, expectedlen);
			return (-1);
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
		FINSerror(pdrvPvt, pasynUser, FUNCNAME, pdrvPvt->reply[MRES], pdrvPvt->reply[SRES], &(pdrvPvt->reply[RESP]));
		return (-1);
	}

/* extract data */

	switch (pasynUser->reason)
	{
		case FINS_DM_READ:
		case FINS_AR_READ:
		case FINS_WR_READ:
		case FINS_IO_READ:
		case FINS_HR_READ:
		case FINS_TM_READ:
		case FINS_CT_READ:
		case FINS_DM_WRITE:
		case FINS_AR_WRITE:
		case FINS_WR_WRITE:
		case FINS_IO_WRITE:
		case FINS_HR_WRITE:
		case FINS_TM_WRITE:
		case FINS_CT_WRITE:
		{

		/* asynInt16Array */
		
			if (asynSize == sizeof(epicsUInt16))
			{
				int i;
				epicsUInt16 *ptrd = (epicsUInt16 *) data;
                if (address_shift != 0)
                {
				    epicsUInt8 *ptrs = (epicsUInt8 *) &pdrvPvt->reply[RESP];
				    for (i = 0; i < nelements; i++)
                    {
                        ptrd[i] = ptrs[i];
                    }
                }
                else
                {
				    epicsUInt16 *ptrs = (epicsUInt16 *) &pdrvPvt->reply[RESP];
				    for (i = 0; i < nelements; i++)
                    {
                        ptrd[i] = BSWAP16(ptrs[i]);
                    }
                }
					
				asynPrint(pasynUser, ASYN_TRACEIO_DRIVER, "%s: port %s, %s %d 16-bit words.\n", FUNCNAME, pdrvPvt->portName, SWAPT, nelements);
			}
			else
			
		/* asynInt32 * 1 */
		
			{			
				int i;
				epicsUInt32 *ptrd = (epicsUInt32 *) data;
                if (address_shift != 0)
                {
				    epicsUInt8 *ptrs = (epicsUInt8 *) &pdrvPvt->reply[RESP];
                    for (i = 0; i < nelements; i++)
                    {
                        ptrd[i] = (epicsUInt32) ptrs[i];
                    }
                }
                else
                {
				    epicsUInt16 *ptrs = (epicsUInt16 *) &pdrvPvt->reply[RESP];
                    for (i = 0; i < nelements; i++)
                    {
                        ptrd[i] = (epicsUInt32) BSWAP16(ptrs[i]);
                    }
                }
					
				asynPrint(pasynUser, ASYN_TRACEIO_DRIVER, "%s: port %s, %s %d 16-bit word.\n", FUNCNAME, pdrvPvt->portName, SWAPT, nelements);
			}
			
		/* check the number of elements received */
		
			if (transfered)
			{
                if (address_shift != 0)
                {
				    *transfered = (recvlen - RESP) / sizeof(epicsUInt8);
                }
                else
                {
				    *transfered = (recvlen - RESP) / sizeof(epicsUInt16);
                }
			}
			
			break;
		}

		case FINS_DM_READ_32:
		case FINS_AR_READ_32:
		case FINS_WR_READ_32:
		case FINS_IO_READ_32:
		case FINS_HR_READ_32:
		case FINS_DM_WRITE_32:
		case FINS_AR_WRITE_32:
		case FINS_WR_WRITE_32:
		case FINS_IO_WRITE_32:
		case FINS_HR_WRITE_32:
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

		case FINS_STATUS:
		{
			epicsInt16 *rep = (epicsInt16 *) &pdrvPvt->reply[RESP + 0];
			epicsInt16 *dat = (epicsInt16 *) data;
			int i;
				
			for (i = 0; i < 13; i++)
			{
				*dat++ = BSWAP16(*rep++);
			}

			if (transfered)
			{
				*transfered = 13;
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
			unsigned char  *rep = (unsigned char *)  &pdrvPvt->reply[RESP + 0];
			epicsInt16 *dat = (epicsInt16 *) data;
			int i;
				
			/* year (2 digit), month, date, hour, minute, second, day (Sun=0) */
			for (i = 0; i < 7; i++)
			{
				*dat++ = bcd2int(*rep++);
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
	
static int finsSocketWrite(drvPvt *pdrvPvt, asynUser *pasynUser, const void *data, size_t nwords, epicsUInt16 address, size_t asynSize)
{
	static const char *FUNCNAME = "finsSocketWrite";
	int recvlen, sendlen;
	unsigned expectedlen;
    finsTCPHeader fins_header;
	epicsTimeStamp ets, ete;
    /* if user_data != 0x0 then we perform a bit rather than word operation */
    unsigned user_data = 0x0, address_shift = 0x0, bit_number = 0x0;
    memcpy(&user_data, &(pasynUser->userData), sizeof(user_data));
    address_shift = (user_data >> 8);
    bit_number = (user_data & 0xff);
	
/* initialise header */

	pdrvPvt->message[ICF] = 0x80;
	pdrvPvt->message[RSV] = 0x00;
	pdrvPvt->message[GCT] = FINS_GATEWAY;

	pdrvPvt->message[DNA] = pdrvPvt->dna;
	pdrvPvt->message[DA1] = pdrvPvt->node;
	pdrvPvt->message[DA2] = 0x00;

	pdrvPvt->message[SNA] = pdrvPvt->sna;
	pdrvPvt->message[SA1] = pdrvPvt->client_node;
	pdrvPvt->message[SA2] = 0x00;
	
	switch (pasynUser->reason)
	{
	
	/* Memory write */
	
		case FINS_DM_WRITE:
		case FINS_DM_WRITE_NOREAD:
		case FINS_AR_WRITE:
		case FINS_AR_WRITE_NOREAD:
		case FINS_WR_WRITE:
		case FINS_WR_WRITE_NOREAD:
		case FINS_IO_WRITE:
		case FINS_IO_WRITE_NOREAD:
		case FINS_HR_WRITE:
		case FINS_HR_WRITE_NOREAD:
		case FINS_CT_WRITE:
		case FINS_TM_WRITE:
		{
			pdrvPvt->message[MRC] = 0x01;
			pdrvPvt->message[SRC] = 0x02;
				
		/* memory type */

			switch (pasynUser->reason)
			{	
				case FINS_DM_WRITE:
				case FINS_DM_WRITE_NOREAD:
				{
					pdrvPvt->message[COM] = DM - address_shift;
					break;
				}
				
				case FINS_AR_WRITE:
				case FINS_AR_WRITE_NOREAD:
				{
					pdrvPvt->message[COM] = AR - address_shift;
					break;
				}

				case FINS_WR_WRITE:
				case FINS_WR_WRITE_NOREAD:
				{
					pdrvPvt->message[COM] = WR - address_shift;
					break;
				}
				
				case FINS_IO_WRITE:
				case FINS_IO_WRITE_NOREAD:
				{
					pdrvPvt->message[COM] = IO - address_shift;
					break;
				}

				case FINS_HR_WRITE:
				case FINS_HR_WRITE_NOREAD:
				{
					pdrvPvt->message[COM] = HR - address_shift;
					break;
				}
				
				case FINS_CT_WRITE:
				{
					pdrvPvt->message[COM] = CT - address_shift;
                    address |= 0x8000;
                    bit_number = 0; /* completion flag */
					break;
				}

				case FINS_TM_WRITE:
				{
					pdrvPvt->message[COM] = TM - address_shift;
                    bit_number = 0; /* completion flag */
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
			pdrvPvt->message[COM+3] = bit_number;

		/* length */

			pdrvPvt->message[COM+4] = (char)(nwords >> 8);
			pdrvPvt->message[COM+5] = nwords & 0xff;

		/* asynInt16Array */
		
			if (asynSize == sizeof(epicsUInt16))
			{
				int i;
				epicsUInt16 *ptrs = (epicsUInt16 *) data;
                if (address_shift != 0)
                {
				    epicsUInt8 *ptrd = (epicsUInt8 *) &pdrvPvt->message[COM + 6];
				    for (i = 0; i < nwords; i++)
				    {
					    ptrd[i] = (epicsUInt8)ptrs[i];
				    }
                }
                else
                {
				    epicsUInt16 *ptrd = (epicsUInt16 *) &pdrvPvt->message[COM + 6];
				    for (i = 0; i < nwords; i++)
				    {
					    ptrd[i] = BSWAP16(ptrs[i]);
				    }
                }

				asynPrint(pasynUser, ASYN_TRACEIO_DRIVER, "%s: port %s, %s %d 16-bit words.\n", FUNCNAME, pdrvPvt->portName, SWAPT, nwords);
			}
			else
			
		/* asynInt32 * 1 */
		
			{
				int i;
				epicsUInt32 *ptrs = (epicsUInt32 *) data;
                if (address_shift != 0)
                {
				    epicsUInt8 *ptrd = (epicsUInt8 *) &pdrvPvt->message[COM + 6];
				    for (i = 0; i < nwords; i++)
                    {
                        ptrd[i] = ptrs[i];
                    }
                }
                else
                {
				    epicsUInt16 *ptrd = (epicsUInt16 *) &pdrvPvt->message[COM + 6];
				    for (i = 0; i < nwords; i++)
                    {
                        ptrd[i] = BSWAP16((epicsUInt16) ptrs[i]);
                    }
                }

				asynPrint(pasynUser, ASYN_TRACEIO_DRIVER, "%s: port %s, %s %d 16-bit word.\n", FUNCNAME, pdrvPvt->portName, SWAPT, nwords);				
			}
			
            if (address_shift != 0)
            {
			    sendlen = (int)(COM + 6 + nwords * sizeof(unsigned char));
            }
            else
            {
			    sendlen = (int)(COM + 6 + nwords * sizeof(short));
			}
			break;
		}

		case FINS_DM_WRITE_32:
		case FINS_DM_WRITE_32_NOREAD:
		case FINS_AR_WRITE_32:
		case FINS_AR_WRITE_32_NOREAD:
		case FINS_WR_WRITE_32:
		case FINS_WR_WRITE_32_NOREAD:
		case FINS_IO_WRITE_32:
		case FINS_IO_WRITE_32_NOREAD:
		case FINS_HR_WRITE_32:
		case FINS_HR_WRITE_32_NOREAD:
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

				case FINS_WR_WRITE_32:
				case FINS_WR_WRITE_32_NOREAD:
				{
					pdrvPvt->message[COM] = WR;
					break;
				}
				
				case FINS_IO_WRITE_32:
				case FINS_IO_WRITE_32_NOREAD:
				{
					pdrvPvt->message[COM] = IO;
					break;
				}
				case FINS_HR_WRITE_32:
				case FINS_HR_WRITE_32_NOREAD:
				{
					pdrvPvt->message[COM] = HR;
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
	
	if ( pdrvPvt->tcp_protocol && (send_fins_header(&fins_header, pdrvPvt->fd, pdrvPvt->portName, pasynUser, sendlen, 0) < 0) )
	{
		return (-1);
	}
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

	    if ( pdrvPvt->tcp_protocol && (recv_fins_header(&fins_header, pdrvPvt->fd, pdrvPvt->portName, pasynUser, 0) < 0) )
	    {
		    return (-1);
	    }
		if ((recvlen = socket_recv(pdrvPvt->fd, pdrvPvt->reply, FINS_MAX_MSG, 0)) < 0)
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, recvfrom() with %s.\n", FUNCNAME, pdrvPvt->portName, socket_errmsg());
			return (-1);
		}
		expectedlen = fins_header.length - 8;
		if ( pdrvPvt->tcp_protocol && (recvlen != expectedlen) )
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, recvfrom() incorrect size %d != %d.\n", FUNCNAME, pdrvPvt->portName, recvlen, expectedlen);
			return (-1);
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
		FINSerror(pdrvPvt, pasynUser, FUNCNAME, pdrvPvt->reply[MRES], pdrvPvt->reply[SRES], &(pdrvPvt->reply[RESP]));
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
	const char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_READ:		
		case FINS_AR_READ:		
		case FINS_WR_READ:
		case FINS_IO_READ:
		case FINS_HR_READ:
		case FINS_CT_READ:
		case FINS_TM_READ:
		case FINS_DM_READ_32:	
		case FINS_AR_READ_32:
		case FINS_WR_READ_32:
		case FINS_IO_READ_32:
		case FINS_HR_READ_32:
		case FINS_CYCLE_TIME_MEAN:
		case FINS_CYCLE_TIME_MAX:
		case FINS_CYCLE_TIME_MIN:
		case FINS_CPU_STATUS:
		case FINS_CPU_MODE:
		{
            type = FINS_COMMANDS_STR[pasynUser->reason];
            break;
        }

	/* this gets called at initialisation by write methods */
	
		case FINS_DM_WRITE:
		case FINS_IO_WRITE:
		case FINS_AR_WRITE:
		case FINS_WR_WRITE:
		case FINS_HR_WRITE:
		case FINS_CT_WRITE:
		case FINS_TM_WRITE:
		case FINS_DM_WRITE_32:
		case FINS_IO_WRITE_32:
		case FINS_AR_WRITE_32:
		case FINS_WR_WRITE_32:
		case FINS_HR_WRITE_32:
		{
			type = "WRITE";
			break;
		}

		case FINS_DM_WRITE_NOREAD:
		case FINS_IO_WRITE_NOREAD:
		case FINS_AR_WRITE_NOREAD:
		case FINS_WR_WRITE_NOREAD:
		case FINS_HR_WRITE_NOREAD:
		case FINS_DM_WRITE_32_NOREAD:
		case FINS_IO_WRITE_32_NOREAD:
		case FINS_AR_WRITE_32_NOREAD:
		case FINS_WR_WRITE_32_NOREAD:
		case FINS_HR_WRITE_32_NOREAD:
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
	const char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE:
		case FINS_DM_WRITE_NOREAD:
		case FINS_AR_WRITE:
		case FINS_AR_WRITE_NOREAD:
		case FINS_WR_WRITE:
		case FINS_WR_WRITE_NOREAD:
		case FINS_IO_WRITE:
		case FINS_IO_WRITE_NOREAD:
		case FINS_HR_WRITE:
		case FINS_HR_WRITE_NOREAD:
		case FINS_CT_WRITE:
		case FINS_TM_WRITE:
		case FINS_CYCLE_TIME_RESET:
		case FINS_DM_WRITE_32:
		case FINS_DM_WRITE_32_NOREAD:
		case FINS_AR_WRITE_32:
		case FINS_AR_WRITE_32_NOREAD:
		case FINS_WR_WRITE_32:
		case FINS_WR_WRITE_32_NOREAD:
		case FINS_IO_WRITE_32:	
		case FINS_IO_WRITE_32_NOREAD:		
		case FINS_HR_WRITE_32:		
		case FINS_HR_WRITE_32_NOREAD:
		{
            type = FINS_COMMANDS_STR[pasynUser->reason];
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
		case FINS_WR_WRITE:
		case FINS_WR_WRITE_NOREAD:
		case FINS_IO_WRITE:
		case FINS_IO_WRITE_NOREAD:
		case FINS_HR_WRITE:
		case FINS_HR_WRITE_NOREAD:
		case FINS_CT_WRITE:
		case FINS_TM_WRITE:
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
		case FINS_WR_WRITE_32:
		case FINS_WR_WRITE_32_NOREAD:
		case FINS_IO_WRITE_32:
		case FINS_IO_WRITE_32_NOREAD:
		case FINS_HR_WRITE_32:
		case FINS_HR_WRITE_32_NOREAD:
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

/*** asynFloat64 ************************************************************************************/
/* read a 32bit float */
static asynStatus ReadFloat64(void *pvt, asynUser *pasynUser, epicsFloat64 *value)
{
	static const char *FUNCNAME = "ReadFloat64";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	const char *type = NULL;
    float value_f = 0.0;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_READ_32:	
		case FINS_AR_READ_32:
		case FINS_WR_READ_32:
		case FINS_IO_READ_32:
		case FINS_HR_READ_32:
		{
            type = FINS_COMMANDS_STR[pasynUser->reason];
            break;
        }

	/* this gets called at initialisation by write methods */
	
		case FINS_DM_WRITE_32:
		case FINS_IO_WRITE_32:
		case FINS_AR_WRITE_32:
		case FINS_WR_WRITE_32:
		case FINS_HR_WRITE_32:
		{
			type = "WRITE";
			break;
		}

		default:
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, no such command %d.\n", FUNCNAME, pdrvPvt->portName, addr, pasynUser->reason);
			return (asynError);
		}
	}

	asynPrint(pasynUser, ASYN_TRACE_FLOW, "%s: port %s, addr %d, %s\n", FUNCNAME, pdrvPvt->portName, addr, type);

/* send FINS request */

	if (finsSocketRead(pdrvPvt, pasynUser, (void *)&value_f, 2, addr, NULL, sizeof(float)) < 0)
	{
		return (asynError);
	}
    *value = value_f;
    
	asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "%s: port %s, addr %d, read 2 word.\n", FUNCNAME, pdrvPvt->portName, addr);

	return (asynSuccess);
}


/*** asynInt16Array *******************************************************************************/

static asynStatus ReadInt16Array(void *pvt, asynUser *pasynUser, epicsInt16 *value, size_t nelements, size_t *nIn)
{
	static const char *FUNCNAME = "ReadInt16Array";
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	int addr;
	asynStatus status;
	const char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_READ:
		case FINS_AR_READ:
		case FINS_WR_READ:
		case FINS_IO_READ:
		case FINS_HR_READ:
		case FINS_CLOCK_READ:
		case FINS_STATUS:
		{
            type = FINS_COMMANDS_STR[pasynUser->reason];
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
		case FINS_WR_READ:
		case FINS_IO_READ:
		case FINS_HR_READ:
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
		
		case FINS_STATUS:
		{
			if (nelements != 13)
			{
				asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, addr %d, FINS_STATUS size != 13.\n", FUNCNAME, pdrvPvt->portName, addr);
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
	const char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE:
		case FINS_AR_WRITE:
		case FINS_WR_WRITE:
		case FINS_IO_WRITE:
		case FINS_HR_WRITE:
		{
            type = FINS_COMMANDS_STR[pasynUser->reason];
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
		case FINS_WR_WRITE:
		case FINS_IO_WRITE:
		case FINS_HR_WRITE:
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
	const char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_READ_32:
		case FINS_AR_READ_32:
		case FINS_WR_READ_32:
		case FINS_IO_READ_32:
		case FINS_HR_READ_32:
		case FINS_CYCLE_TIME:
		{
            type = FINS_COMMANDS_STR[pasynUser->reason];
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
		case FINS_WR_READ_32:
		case FINS_IO_READ_32:
		case FINS_HR_READ_32:
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
	const char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE_32:
		case FINS_AR_WRITE_32:
		case FINS_WR_WRITE_32:
		case FINS_IO_WRITE_32:
		case FINS_HR_WRITE_32:
		{
            type = FINS_COMMANDS_STR[pasynUser->reason];
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
		case FINS_WR_WRITE_32:
		case FINS_IO_WRITE_32:
		case FINS_HR_WRITE_32:
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
	const char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_READ_32:
		case FINS_AR_READ_32:
		case FINS_WR_READ_32:
		case FINS_IO_READ_32:
		case FINS_HR_READ_32:
		{
            type = FINS_COMMANDS_STR[pasynUser->reason];
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
		case FINS_WR_READ_32:
		case FINS_IO_READ_32:
		case FINS_HR_READ_32:
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
	const char *type = NULL;
	
	status = pasynManager->getAddr(pasynUser, &addr);
	
	if (status != asynSuccess)
	{
		return (status);
	}

/* check reason */

	switch (pasynUser->reason)
	{
		case FINS_DM_WRITE_32:
		case FINS_AR_WRITE_32:
		case FINS_WR_WRITE_32:
		case FINS_IO_WRITE_32:
		case FINS_HR_WRITE_32:
        {
            type = FINS_COMMANDS_STR[pasynUser->reason];
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
		case FINS_WR_WRITE_32:
		case FINS_IO_WRITE_32:
		case FINS_HR_WRITE_32:
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
    int i = 0;
    unsigned user_data = 0x0;
	drvPvt *pdrvPvt = (drvPvt *) pvt;
	if (drvInfo)
	{
		if (strcmp("FINS_DM_READ", drvInfo) == 0)
		{
			pasynUser->reason = FINS_DM_READ;
		}
        else
		if (sscanf(drvInfo, "FINS_DM_READ_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_DM_READ;
			user_data = (0x80 << 8) + i;
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
		if (sscanf(drvInfo, "FINS_DM_WRITE_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_DM_WRITE;
			user_data = (0x80 << 8) + i;
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
		if (sscanf(drvInfo, "FINS_IO_READ_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_IO_READ;
			user_data = (0x80 << 8) + i;
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
		if (sscanf(drvInfo, "FINS_IO_WRITE_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_IO_WRITE;
			user_data = (0x80 << 8) + i;
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
		if (sscanf(drvInfo, "FINS_AR_READ_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_AR_READ;
			user_data = (0x80 << 8) + i;
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
		if (sscanf(drvInfo, "FINS_AR_WRITE_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_AR_WRITE;
			user_data = (0x80 << 8) + i;
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
		if (strcmp("FINS_WR_READ", drvInfo) == 0)
		{
			pasynUser->reason = FINS_WR_READ;
		}
        else
		if (sscanf(drvInfo, "FINS_WR_READ_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_WR_READ;
			user_data = (0x80 << 8) + i;
		}
        else
		if (strcmp("FINS_WR_READ_32", drvInfo) == 0)
		{
			pasynUser->reason = FINS_WR_READ_32;
		}
		else
		if (strcmp("FINS_WR_WRITE", drvInfo) == 0)
		{
			pasynUser->reason = FINS_WR_WRITE;
		}
		else
		if (sscanf(drvInfo, "FINS_WR_WRITE_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_WR_WRITE;
			user_data = (0x80 << 8) + i;
		}
		else
		if (strcmp("FINS_WR_WRITE_NOREAD", drvInfo) == 0)
		{
			pasynUser->reason = FINS_WR_WRITE_NOREAD;
		}
		else
		if (strcmp("FINS_WR_WRITE_32", drvInfo) == 0)
		{
			pasynUser->reason = FINS_WR_WRITE_32;
		}
		else
		if (strcmp("FINS_WR_WRITE_32_NOREAD", drvInfo) == 0)
		{
			pasynUser->reason = FINS_WR_WRITE_32_NOREAD;
		}
		else
		if (strcmp("FINS_HR_READ", drvInfo) == 0)
		{
			pasynUser->reason = FINS_HR_READ;
		}
        else
		if (sscanf(drvInfo, "FINS_HR_READ_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_HR_READ;
			user_data = (0x80 << 8) + i;
		}
        else
		if (strcmp("FINS_HR_READ_32", drvInfo) == 0)
		{
			pasynUser->reason = FINS_HR_READ_32;
		}
		else
		if (strcmp("FINS_HR_WRITE", drvInfo) == 0)
		{
			pasynUser->reason = FINS_HR_WRITE;
		}
		else
		if (sscanf(drvInfo, "FINS_HR_WRITE_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_HR_WRITE;
			user_data = (0x80 << 8) + i;
		}
		else
		if (strcmp("FINS_HR_WRITE_NOREAD", drvInfo) == 0)
		{
			pasynUser->reason = FINS_HR_WRITE_NOREAD;
		}
		else
		if (strcmp("FINS_HR_WRITE_32", drvInfo) == 0)
		{
			pasynUser->reason = FINS_HR_WRITE_32;
		}
		else
		if (strcmp("FINS_HR_WRITE_32_NOREAD", drvInfo) == 0)
		{
			pasynUser->reason = FINS_HR_WRITE_32_NOREAD;
		}
		else
		if (strcmp("FINS_CT_READ", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CT_READ;
		}
        else
		if (sscanf(drvInfo, "FINS_CT_READ_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_CT_READ;
			user_data = (0x80 << 8) + i;
		}
		else
		if (strcmp("FINS_CT_WRITE", drvInfo) == 0)
		{
			pasynUser->reason = FINS_CT_WRITE;
		}
		else
		if (sscanf(drvInfo, "FINS_CT_WRITE_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_CT_WRITE;
			user_data = (0x80 << 8) + i;
		}
		else
		if (strcmp("FINS_TM_READ", drvInfo) == 0)
		{
			pasynUser->reason = FINS_TM_READ;
		}
        else
		if (sscanf(drvInfo, "FINS_TM_READ_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_TM_READ;
			user_data = (0x80 << 8) + i;
		}
		else
		if (strcmp("FINS_TM_WRITE", drvInfo) == 0)
		{
			pasynUser->reason = FINS_TM_WRITE;
		}
		else
		if (sscanf(drvInfo, "FINS_TM_WRITE_B%d", &i) == 1)
		{
			pasynUser->reason = FINS_TM_WRITE;
			user_data = (0x80 << 8) + i;
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
		if (strcmp("FINS_STATUS", drvInfo) == 0)
		{
			pasynUser->reason = FINS_STATUS;
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
        memcpy(&(pasynUser->userData), &user_data, sizeof(user_data)); 

		asynPrint(pasynUser, ASYN_TRACEIO_DEVICE, "drvUserCreate: port %s, %s = %d\n", pdrvPvt->portName, drvInfo, pasynUser->reason);

		return (asynSuccess);
	}

	return (asynError);
}

static int socket_recv(SOCKET fd, char* buffer, int maxlen, int wait_for_all)
{
	fd_set rfds;
	struct timeval tv;
    int recv_len, total_len = 0;
    for(;;)
	{
		if (wait_for_all)
		{
	        recv_len = recv(fd, buffer, maxlen, 0);
		}
		else
		{
			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);
			tv.tv_sec = 0;
			tv.tv_usec = 10 * 1000;
			if ( select((int)fd + 1, &rfds, NULL, NULL, &tv) > 0 )
			{
	            recv_len = recv(fd, buffer, maxlen, 0);			
			}
			else
			{
			    recv_len = 0;
			}
		}
		if (recv_len > 0)
		{
			total_len += recv_len;
		    if (recv_len < maxlen)
			{
			    maxlen -= recv_len;
				buffer += recv_len;
			}
			else
			{
			    break; // all data read 
			}
		}
		else if ( recv_len == 0 )
		{
			break; // no more data
		}
		else // error
		{
		    total_len = -1; // recv() returned error
			break;
		}
	}
	return total_len;	
}

static void init_fins_header(finsTCPHeader* fins_header)
{
	memset(fins_header, 0, sizeof(finsTCPHeader));
    fins_header->header = 0x46494E53; // "FINS" in ASCII
}

static void byteswap_fins_header(finsTCPHeader* fins_header)
{
    int i;
	uint32_t* head = (uint32_t*)fins_header;
	for(i = 0; i < sizeof(finsTCPHeader) / sizeof(uint32_t); ++i)
	{
	    head[i] = BSWAP32(head[i]);
	}
}

static int send_fins_header(finsTCPHeader* fins_header, SOCKET fd, const char* portName, asynUser* pasynUser, int sendlen, int first_header)
{
    int hsend;
    init_fins_header(fins_header);
	if (first_header)
	{
 	    fins_header->length = 12;
	    fins_header->command = 0x00;
	    hsend = 20;
	}
	else
	{
 	    fins_header->length = 8 + sendlen;
	    fins_header->command = 0x02;
	    hsend = 16;
	}
	byteswap_fins_header(fins_header);
	if (send(fd, (const char*)fins_header, hsend, 0) != hsend)
	{
		if (pasynUser != NULL)
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "send_fins_header: port %s, send() failed with %s.\n", portName, socket_errmsg());
		}
		else
		{
			errlogPrintf("send_fins_header: port %s, send() failed with %s.\n", portName, socket_errmsg());
		}
		return (-1);
	}
	return hsend;
}

static const char* finsTCPError(int code)
{
    switch(code)
	{
	    case 0x0:
		    return "Normal."; // not an error
			break;
			
	    case 0x1:
		    return "Header is not 'FINS' (ASCII CODE)."; // not an error
			break;

	    case 0x2:
		    return "The data length is too long.";
			break;
			
	    case 0x3:
		    return "The command is not supported.";
			break;
		
	    case 0x20:
		    return "All connections are in use.";
			break;

		case 0x21:
		    return "The specified node is already connected.";
			break;

		case 0x22:
		    return "Attempt to access a protected node from an unspecified IP address.";
			break;

		case 0x23:
		    return "The client FINS node address is out of range.";
			break;

		case 0x24:
		    return "The same FINS node address is being used by the client and the server.";
			break;

		case 0x25:
		    return "All the node addresses available for allocation have been used.";
			break;
			
		default:
		    return "Unknown error code.";
			break;		
	}
}
static int recv_fins_header(finsTCPHeader* fins_header, SOCKET fd, const char* portName, asynUser* pasynUser, int first_header)
{
    int hrecv, command_ret;
	if (first_header)
	{
 	    hrecv = 24;
		command_ret = 0x01;
	}
	else
	{
	    hrecv = 16;
		command_ret = 0x02;
	}
	if (socket_recv(fd, (char*)fins_header, hrecv, 1) != hrecv)
	{
		if (pasynUser != NULL)
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "recv_fins_header: port %s, recv() failed with %s.\n", portName, socket_errmsg());
		}
		else
		{
			errlogPrintf("recv_fins_header: port %s, recv() failed with %s.\n", portName, socket_errmsg());
		}
		return (-1);
	}
	byteswap_fins_header(fins_header);
	if (fins_header->error_code != 0x0)
	{
		if (pasynUser != NULL)
		{
			asynPrint(pasynUser, ASYN_TRACE_ERROR, "recv_fins_header: port %s, FINS error: %s\n", 
					portName, finsTCPError(fins_header->error_code));
		}
		else
		{
			errlogPrintf("recv_fins_header: port %s, FINS error: %s\n", portName, finsTCPError(fins_header->error_code));
		}
		return (-1);
	}
	if (fins_header->command != command_ret)
	{
		if (pasynUser != NULL)
		{
		    asynPrint(pasynUser, ASYN_TRACE_ERROR, "recv_fins_header: port %s, incorrect command returned %d != %d.\n", 
					portName, fins_header->command, command_ret);
		}
		else
		{
		    errlogPrintf("recv_fins_header: port %s, incorrect command returned %d != %d.\n", 
					portName, fins_header->command, command_ret);
		}
		return (-1);
	}
	return hrecv;
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

static void FINSerror(drvPvt *pdrvPvt, asynUser *pasynUser, const char *name, unsigned char mres, unsigned char sres, const char* resp)
{
    const unsigned char* uresp = (const unsigned char*)resp;
    if (sres & 0x40)
    {
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, Non-fatal CPU Unit Error Flag\n", name, pdrvPvt->portName);        
        sres ^= 0x40;
    }
    if (sres & 0x80)
    {
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, Fatal CPU Unit Error Flag\n", name, pdrvPvt->portName);
        sres ^= 0x80;
    }
	if (mres & 0x80)
	{
		asynPrint(pasynUser, ASYN_TRACE_ERROR, "%s: port %s, Network Relay Error Flag - from network address 0x%02x node address 0x%02x when trying to contact node 0x%02x\n", name, pdrvPvt->portName, uresp[0], uresp[1], pdrvPvt->node);
		mres ^= 0x80;
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

int finsTest(char *address, char* protocol)
{
	SOCKET fd;
	struct sockaddr_in addr;
	const int addrlen = sizeof(struct sockaddr_in);
	uint8_t node, client_node;
	unsigned char *message;
	int recvlen, sendlen = 0;
	unsigned expectedlen;
	int tcp_protocol = 0;
	finsTCPHeader fins_header;
	unsigned char checksum = 0;
	unsigned char ck[2];
	int i;
//	DebugBreak();
	if (!strcmp(protocol, "TCP"))
	{
	    tcp_protocol = 1;
	}
	
	message = (unsigned char *) callocMustSucceed(1, FINS_MAX_MSG, "finsTest");
	
/* open a datagram socket */
	
	if (tcp_protocol)
	{
	    fd = epicsSocketCreate(PF_INET, SOCK_STREAM, 0);
	}
	else
	{
	    fd = epicsSocketCreate(PF_INET, SOCK_DGRAM, 0);
	}
	if (fd < 0)
	{
		errlogPrintf("finsTest: socket %s\n", socket_errmsg());
		return (-1);
	}
	
	memset(&(addr), 0, addrlen);

/* ask for a free port for incoming UDP packets */

	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(0);

	if (!tcp_protocol)
	{
/* bind socket to address */
		if (bind(fd, (struct sockaddr *) &addr, addrlen) < 0)
		{
			errlogPrintf("finsTest: bind %s\n", socket_errmsg());
			epicsSocketDestroy(fd);
			return (-1);
		}
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

		errlogSevPrintf(errlogInfo, "finsTest: port %d bound\n", ntohs(name.sin_port));
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
		errlogPrintf("finsTest: Bad IP address %s\n", address);
		epicsSocketDestroy(fd);
		return (-1);
	}

/* node address is last byte of IP address */
		
	node = ntohl(addr.sin_addr.s_addr) & 0xff;
		
	errlogSevPrintf(errlogInfo, "PLC node %d\n", node);

	if (connect(fd, (const struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		errlogPrintf("connect() to %s port %hu with %s.\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), socket_errmsg());
		epicsSocketDestroy(fd);
		return (-1);
	}

	if (tcp_protocol)
	{
		if (send_fins_header(&fins_header, fd, "finsTest", NULL, 4, 1) < 0)
		{
			epicsSocketDestroy(fd);
			return (-1);
		}
		if (recv_fins_header(&fins_header, fd, "finsTest", NULL, 1) < 0)
		{
			epicsSocketDestroy(fd);
			return (-1);
		}
		errlogSevPrintf(errlogInfo, "Client node %d server node %d\n", fins_header.extra[0], fins_header.extra[1]);	
		client_node = fins_header.extra[0];
	}
	else
	{
		client_node = FINS_SOURCE_ADDR;
	}

	
	/* send a simple FINS command */

	message[ICF] = 0x80; /* command, response required */
	message[RSV] = 0x00;
	message[GCT] = FINS_GATEWAY;

	message[DNA] = 0x0;  
	message[DA1] = node;		/* destination node */
	message[DA2] = 0x00;

	message[SNA] = 0x0;   
	message[SA1] = client_node;		/* source node */
	message[SA2] = 0x00;

	message[MRC] = 0x01;
	message[SRC] = 0x01;
	message[COM] = DM;		/* data memory read */
#if 0
	message[COM+1] = 100 >> 8;
	message[COM+2] = 100 & 0xff;
	message[COM+3] = 0x00;		/* start address */
#else
	message[COM+1] = (1000 >> 8) & 0xff;
	message[COM+2] = 1000 & 0xff;
	message[COM+3] = (1000 >> 16) & 0xff;		/* start address */
#endif

	message[COM+4] = 2 >> 8;
	message[COM+5] = 2 & 0xff;	/* length */
	sendlen = COM + 6;

	if ( tcp_protocol && (send_fins_header(&fins_header, fd, "finsTest", NULL, sendlen, 0) < 0) )
	{
		epicsSocketDestroy(fd);
		return (-1);
	}

	for (i=0; i<16; ++i)
	{
		checksum ^= ((unsigned char*)&fins_header)[i];
//		printf("%02x ", ((unsigned char*)&fins_header)[i]);
	}
	for (i=0; i<sendlen; ++i)
	{
		checksum ^= message[i];
	}
	ck[0] = ( (checksum >> 4) & 0x0f ) + '0';
	ck[1] = ( checksum & 0x0f ) + '0';

//	for(i=0; i<sendlen; ++i)
//	{
//		printf("%02x ", message[i]);
//	}
/* send request */

	if (send(fd, message, sendlen, 0) != sendlen)
	{
		errlogPrintf("send() to %s port %hu with %s.\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), socket_errmsg());
		epicsSocketDestroy(fd);
		return (-1);
	}

	// send checksum
//	if (send(fd, ck, 2, 0) != 2)
//	{
//		printf("send() to %s port %hu with %s.\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), socket_errmsg());
//		epicsSocketDestroy(fd);
//		return (-1);
//	}

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
				errlogPrintf("finsTest: select %s\n", socket_errmsg());	
				return (-1);
				break;
			}
			
			case 0:
			{
				errlogPrintf("finsTest: select timeout\n");
				return (-1);
				break;
			}

			default:
			{
				break;
			}
		}
	}


	    if ( tcp_protocol && (recv_fins_header(&fins_header, fd, "finsTest", NULL, 0) < 0) )
	    {
			epicsSocketDestroy(fd);
		    return (-1);
	    }

		if ((recvlen = socket_recv(fd, (char*)message, FINS_MAX_MSG, 0)) < 0)
		{
			errlogPrintf("finsTest: recv %s.\n", socket_errmsg());
			epicsSocketDestroy(fd);
			return (-1);
		}
	expectedlen = fins_header.length - 8;
	if ( tcp_protocol && (recvlen != expectedlen) )
	{
		errlogPrintf("finsTest: recvfrom incorrect size %d != %d.\n", recvlen, expectedlen);
		epicsSocketDestroy(fd);
		return (-1);
	}
	{
		int i;
		
		for (i = 0; i < recvlen; i++)
		{
			errlogPrintf("0x%02x ", message[i]);
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
				errlogPrintf("%s 0x%02x\n", error01, message[SRES]);
				break;
			}
		
			case 0x02:
			{
				errlogPrintf("%s 0x%02x\n", error02, message[SRES]);
				break;
			}
		
			case 0x03:
			{
				errlogPrintf("%s 0x%02x\n", error03, message[SRES]);
				break;
			}
		
			case 0x04:
			{
				errlogPrintf("%s 0x%02x\n", error04, message[SRES]);
				break;
			}
		
			case 0x05:
			{
				errlogPrintf("%s 0x%02x\n", error05, message[SRES]);
				break;
			}
		
			case 0x10:
			{
				errlogPrintf("%s 0x%02x\n", error10, message[SRES]);
				break;
			}
		
			case 0x11:
			{
				errlogPrintf("%s 0x%02x\n", error11, message[SRES]);
				break;
			}
		
			case 0x20:
			{
				errlogPrintf("%s 0x%02x\n", error20, message[SRES]);
				break;
			}
		
			case 0x21:
			{
				errlogPrintf("%s 0x%02x\n", error21, message[SRES]);
				break;
			}
		
			case 0x22:
			{
				errlogPrintf("%s 0x%02x\n", error22, message[SRES]);
				break;
			}
		
			case 0x23:
			{
				errlogPrintf("%s 0x%02x\n", error23, message[SRES]);
				break;
			}
		
			case 0x24:
			{
				errlogPrintf("%s 0x%02x\n", error24, message[SRES]);
				break;
			}
		
			case 0x25:
			{
				errlogPrintf("%s 0x%02x\n", error25, message[SRES]);
				break;
			}
		
			case 0x26:
			{
				errlogPrintf("%s 0x%02x\n", error26, message[SRES]);
				break;
			}
		
			case 0x30:
			{
				errlogPrintf("%s 0x%02x\n", error30, message[SRES]);
				break;
			}
		
			case 0x40:
			{
				errlogPrintf("%s 0x%02x\n", error40, message[SRES]);
				break;
			}
		
			default:
			{
				errlogPrintf("Error 0x%02x/0x%02x\n", message[MRES], message[SRES]);
				break;
			}
		}
	}
		
	epicsSocketDestroy(fd);
	
	return (0);
}

static const iocshArg finsTestArg0 = { "IP address", iocshArgString };
static const iocshArg finsTestArg1 = { "protocol", iocshArgString };

static const iocshArg *finsTestArgs[] = { &finsTestArg0, &finsTestArg1 };
static const iocshFuncDef finsTestFuncDef = { "finsTest", 2, finsTestArgs};

static void finsTestCallFunc(const iocshArgBuf *args)
{
	finsTest(args[0].sval, args[1].sval);
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
