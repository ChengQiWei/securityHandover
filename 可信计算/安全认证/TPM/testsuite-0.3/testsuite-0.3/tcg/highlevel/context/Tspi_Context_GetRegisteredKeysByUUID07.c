/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004-2006
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * NAME
 *	Tspi_Context_GetRegisteredKeysByUUID07.c
 *
 * DESCRIPTION
 *	This test will print the information in the TSS_KM_KEYINFO structures
 *	returned by Tspi_Context_GetRegisteredKeysByUUID.
 *
 * ALGORITHM
 *	Setup:
 *		Create
 *		Connect
 *		Get TPM Object
 *		Create Object
 *		Load Key by UUID
 *		Get Policy Object for the srkUsagePolicy
 *		Set Secret for the srkUsagePolicy
 *		Set Secret
 *		Set Secret
 *		Create the hKey with the hSRK wrapping key
 *		SetAttribUint32
 *		SetAttribUint32
 *		Register the hKey
 *
 *	Test:	Call GetRegisteredKeyByUUIDCreateKey. If it is not a success
 *		Call the Common Errors
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Close hKey Object
 *		Close the context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1 and 1.2
 *
 *
 * HISTORY
 *	Author:	Kathy Robertson
 *	Date:	June 2004
 *	Email:	klrobert@us.ibm.com
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdlib.h>

#include "common.h"




int main(int argc, char **argv)
{
	char		version;

	version = parseArgs(argc, argv);
	if (version)
		main_v1_1();
	else
		print_wrongVersion();
}

void
print_KM_KEYINFO(TSS_KM_KEYINFO *k)
{
	printf("Version     : %hhu.%hhu.%hhu.%hhu\n", k->versionInfo.bMajor, k->versionInfo.bMinor,
	       k->versionInfo.bRevMajor, k->versionInfo.bRevMinor);
	printf("UUID        : %08x %04hx %04hx %02hhx %02hhx %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
	       k->keyUUID.ulTimeLow, k->keyUUID.usTimeMid, k->keyUUID.usTimeHigh,
	       k->keyUUID.bClockSeqHigh, k->keyUUID.bClockSeqLow,
	       k->keyUUID.rgbNode[0] & 0xff, k->keyUUID.rgbNode[1] & 0xff,
	       k->keyUUID.rgbNode[2] & 0xff, k->keyUUID.rgbNode[3] & 0xff,
	       k->keyUUID.rgbNode[4] & 0xff, k->keyUUID.rgbNode[5] & 0xff);
	printf("parent UUID : %08x %04hx %04hx %02hhx %02hhx %02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
	       k->parentKeyUUID.ulTimeLow, k->parentKeyUUID.usTimeMid, k->parentKeyUUID.usTimeHigh,
	       k->parentKeyUUID.bClockSeqHigh, k->parentKeyUUID.bClockSeqLow,
	       k->parentKeyUUID.rgbNode[0] & 0xff, k->parentKeyUUID.rgbNode[1] & 0xff,
	       k->parentKeyUUID.rgbNode[2] & 0xff, k->parentKeyUUID.rgbNode[3] & 0xff,
	       k->parentKeyUUID.rgbNode[4] & 0xff, k->parentKeyUUID.rgbNode[5] & 0xff);
	printf("auth        : %s\n", k->bAuthDataUsage ? "YES" : "NO");
	if (k->ulVendorDataLength)
		printf("vendor data : \"%s\" (%u bytes)\n", k->rgbVendorData,
		       k->ulVendorDataLength);
	else
		printf("vendor data : (0 bytes)\n");

	printf("\n");
}

int
main_v1_1(void){

	char		*nameOfFunction = "Tspi_Context_GetRegisteredKeysByUUID07";
	TSS_HCONTEXT	hContext;
	TSS_HTPM	hTPM;
	TSS_FLAG	initFlags;
	TSS_HKEY	hKey;
	TSS_HKEY	hSRK;
	TSS_RESULT	result;
	TSS_UUID	migratableSignUUID={1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 2};
	TSS_HPOLICY	srkUsagePolicy;

	UINT32			pulKeyHierarchySize, i;
	TSS_KM_KEYINFO*		ppKeyHierarchy;

	initFlags	= TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_512  |
			TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION |
			TSS_KEY_NOT_MIGRATABLE;

	print_begin_test(nameOfFunction);

		//Create
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		exit(result);
	}
		//Connect
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Load Key by UUID
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#ifndef TESTSUITE_NOAUTH_SRK
		//Get Policy Object for the srkUsagePolicy
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret for the srkUsagePolicy
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
			TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif
		//Create Object
	result = Tspi_Context_CreateObject(hContext,
				TSS_OBJECT_TYPE_RSAKEY,
				initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Create the hKey with the hSRK wrapping key
	result = Tspi_Key_CreateKey(hKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Register the hKey
	result = Tspi_Context_RegisterKey(hContext,
				hKey, TSS_PS_TYPE_SYSTEM, migratableSignUUID,
				TSS_PS_TYPE_SYSTEM, SRK_UUID);
	if (result != TSS_SUCCESS &&
		TSS_ERROR_CODE(result) != TSS_E_KEY_ALREADY_REGISTERED) {
		print_error("Tspi_Context_RegisterKey ", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Register the hKey
	result = Tspi_Context_RegisterKey(hContext,
				hKey, TSS_PS_TYPE_USER, migratableSignUUID,
				TSS_PS_TYPE_SYSTEM, SRK_UUID);
	if (result != TSS_SUCCESS &&
		TSS_ERROR_CODE(result) != TSS_E_KEY_ALREADY_REGISTERED) {
		print_error("Tspi_Context_RegisterKey ", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get Registered Keys By UUID
	result = Tspi_Context_GetRegisteredKeysByUUID(hContext, TSS_PS_TYPE_SYSTEM, NULL,
						      &pulKeyHierarchySize, &ppKeyHierarchy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_RegisterKey ", result);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	for (i = 0; i < pulKeyHierarchySize; i++) {
		printf("Registered key %u:\n", i);
		print_KM_KEYINFO(&ppKeyHierarchy[i]);
	}

	result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_FreeMemory ", result);
		Tspi_Context_Close(hContext);
		exit(result);
	}

	print_success(nameOfFunction, result);
	print_end_test(nameOfFunction);
	Tspi_Context_FreeMemory(hContext, NULL);
	Tspi_Context_CloseObject(hContext, hKey);
	Tspi_Context_Close(hContext);
	exit(0);
}
