TOP=../..

include $(TOP)/configure/CONFIG

# ------------------------
# Build an IOC Application
# ------------------------

PROD_IOC = CS-RF-IOC-01

# CS-RF-IOC-01.dbd will be installed into <top>/dbd
DBD += CS-RF-IOC-01.dbd

# CS-RF-IOC-01.dbd will be created from these files
CS-RF-IOC-01_DBD += base.dbd
CS-RF-IOC-01_DBD += asyn.dbd
CS-RF-IOC-01_DBD += finsUDP.dbd

# CS-RF-IOC-01_registerRecordDeviceDriver.cpp will be created
# CS-RF-IOC-01.dbd
CS-RF-IOC-01_SRCS += CS-RF-IOC-01_registerRecordDeviceDriver.cpp

# These two lines are needed for non-vxWorks builds, such as Linux
CS-RF-IOC-01_SRCS_DEFAULT += CS-RF-IOC-01Main.cpp
CS-RF-IOC-01_SRCS_vxWorks += -nil-

# Add locally compiled object code
#CS-RF-IOC-01_SRCS +=

# The following adds object code from base/src/vxWorks
CS-RF-IOC-01_OBJS_vxWorks += $(EPICS_BASE_BIN)/vxComLibrary

# This line says that this IOC Application depends on the
# xxx Support Module
CS-RF-IOC-01_LIBS += asyn
CS-RF-IOC-01_LIBS += FINS

# We need to link this IOC Application against the EPICS Base libraries
CS-RF-IOC-01_LIBS += $(EPICS_BASE_IOC_LIBS)

# ---------------------------------------------------

include $(TOP)/configure/RULES
