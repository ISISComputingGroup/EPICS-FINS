TOP=../..

include $(TOP)/configure/CONFIG

# -------------------------------
# Build an Diamond Support Module
# -------------------------------

LIBRARY_IOC += FINS

# xxxRecord.dbd will be installed into <top>/dbd
DBD += finsUDP.dbd

# The following are compiled and added to the support library
FINS_SRCS += finsUDP.c
#FINS_SRCS += finsHostlink.c

FINS_LIBS += asyn

# We need to link against the EPICS Base libraries
FINS_LIBS += $(EPICS_BASE_IOC_LIBS)

FINS_SYS_LIBS_WIN32 += ws2_32

# ---------------------------------------------------

include $(TOP)/configure/RULES
