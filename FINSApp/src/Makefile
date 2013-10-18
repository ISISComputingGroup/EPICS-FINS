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

# We need to link against the EPICS Base libraries
FINS_LIBS += $(EPICS_BASE_IOC_LIBS)

# ---------------------------------------------------

include $(TOP)/configure/RULES
