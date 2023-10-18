/*
 * pcclient.h
 *
 * Author:  David Safford <david.safford@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * BIOS specific Content types. These are spread out over 2 specs:
 * "TCG EFI Protocol Specification For TPM Family 1.1 or 1.2" and
 * "TCG PC Client Specific Implementation Specification for Conventional BIOS"
 *
 * BIOS EVENT-1:
 *     PCR       (4 - LE)
 *     Type      (4 - LE)
 *     SHA1      (20)
 *     DataSize  (4 - LE)
 *     Data...
 * BIOS EVENT-2:
 *     PCR       	(4 - LE)
 *     Type      	(4 - LE)
 *     DigestCount	(4 - LE)
 *     Digest ID	(2 - LE)
 *     Digest[]
 *     DataSize  	(4 - LE)
 *     Data[]
 */
#define EV_PREBOOT_CERT            	0x0
#define EV_POST_CODE               	0x1
#define EV_UNUSED                  	0x2
#define EV_NO_ACTION               	0x3
#define EV_SEPARATOR               	0x4
#define EV_ACTION                  	0x5
#define EV_EVENT_TAG               	0x6
#define EV_S_CRTM_CONTENTS         	0x7
#define EV_S_CRTM_VERSION          	0x8
#define EV_CPU_MICROCODE           	0x9
#define EV_PLATFORM_CONFIG_FLAGS   	0xa
#define EV_TABLE_OF_DEVICES        	0xb
#define EV_COMPACT_HASH            	0xc
#define EV_IPL                     	0xd
#define EV_IPL_PARTITION_DATA      	0xe
#define EV_NONHOST_CODE            	0xf
#define EV_NONHOST_CONFIG          	0x10
#define EV_NONHOST_INFO            	0x11
#define EV_OMIT_BOOT_DEVICE_EVENTS 	0x12

char *pcclient_type_low[] = {
	"EV_PREBOOT_CERT",
	"EV_POST_CODE",
	"EV_UNUSED",
	"EV_NO_ACTION",
	"EV_SEPARATOR",
	"EV_ACTION",
	"EV_EVENT_TAG",
	"EV_S_CRTM_CONTENTS",
	"EV_S_CRTM_VERSION",
	"EV_CPU_MICROCODE",
	"EV_PLATFORM_CONFIG_FLAGS",
	"EV_TABLE_OF_DEVICES",
	"EV_COMPACT_HASH",
	"EV_IPL",
	"EV_IPL_PARTITION_DATA",
	"EV_NONHOST_CODE",
	"EV_NONHOST_CONFIG",
	"EV_NONHOST_INFO",
	"EV_OMIT_BOOT_DEVICE_EVENTS"
};

/* TCG EFI Platform Specification For TPM Family 1.1 or 1.2 */
#define EV_EFI_EVENT_BASE                0x80000000
#define EV_EFI_VARIABLE_DRIVER_CONFIG    EV_EFI_EVENT_BASE + 0x1
#define EV_EFI_VARIABLE_BOOT             EV_EFI_EVENT_BASE + 0x2
#define EV_EFI_BOOT_SERVICES_APPLICATION EV_EFI_EVENT_BASE + 0x3
#define EV_EFI_BOOT_SERVICES_DRIVER      EV_EFI_EVENT_BASE + 0x4
#define EV_EFI_RUNTIME_SERVICES_DRIVER   EV_EFI_EVENT_BASE + 0x5
#define EV_EFI_GPT_EVENT                 EV_EFI_EVENT_BASE + 0x6
#define EV_EFI_ACTION                    EV_EFI_EVENT_BASE + 0x7
#define EV_EFI_PLATFORM_FIRMWARE_BLOB    EV_EFI_EVENT_BASE + 0x8
#define EV_EFI_HANDOFF_TABLES            EV_EFI_EVENT_BASE + 0x9
#define EV_EFI_VARIABLE_AUTHORITY        EV_EFI_EVENT_BASE + 0xe0

char *pcclient_type_efi[] = {
	"EV_EFI_EVENT_BASE",
	"EV_EFI_VARIABLE_DRIVER_CONFIG",
	"EV_EFI_VARIABLE_BOOT",
	"EV_EFI_BOOT_SERVICES_APPLICATION",
	"EV_EFI_BOOT_SERVICES_DRIVER",
	"EV_EFI_RUNTIME_SERVICES_DRIVER",
	"EV_EFI_GPT_EVENT",
	"EV_EFI_ACTION",
	"EV_EFI_PLATFORM_FIRMWARE_BLOB",
	"EV_EFI_HANDOFF_TABLES"
};

