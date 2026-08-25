#include <windows.h>
#include "bofdefs.h"
#include "base.c"

BOOL GetRootDN(LDAP* ld, char** rootDN) {
	LDAPMessage* res = NULL;
	char* attrs[] = { "rootDomainNamingContext", NULL };

	if (WLDAP32$ldap_search_s(ld, NULL, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res) != LDAP_SUCCESS) {
		internal_printf("[-] Failed to get root DN\n");
		return FALSE;
	}

	LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
	if (!entry) {
		internal_printf("[-] No root DN entry found\n");
		WLDAP32$ldap_msgfree(res);
		return FALSE;
	}

	PCHAR* values = WLDAP32$ldap_get_values(ld, entry, "rootDomainNamingContext");
	if (!values || !values[0]) {
		internal_printf("[-] Failed to extract rootDomainNamingContext\n");
		WLDAP32$ldap_msgfree(res);
		return FALSE;
	}

	int len = MSVCRT$strlen(values[0]) + 1;
	*rootDN = (char*)intAlloc(len);
	MSVCRT$strcpy(*rootDN, values[0]);

	WLDAP32$ldap_value_free(values);
	WLDAP32$ldap_msgfree(res);
	return TRUE;
}

BOOL CheckDeletedObjectsAccess(LDAP* ld, char* rootDN) {
	LDAPMessage* res = NULL;
	char searchDN[256] = {0};
	char* attrs[] = { "sAMAccountName", NULL };
	ULONG ldapErr = 0;
	LDAP_TIMEVAL timeout = {0};
	LDAPControlA showDeletedControl = {0};
	PLDAPControlA controls[] = { &showDeletedControl, NULL };

	MSVCRT$sprintf(searchDN, "CN=Deleted Objects,%s", rootDN);
	internal_printf("[*] Searching for deleted objects: %s\n", searchDN);

	// Setup SHOW_DELETED control
	showDeletedControl.ldctl_oid = (PCHAR)LDAP_CONTROL_SHOW_DELETED_OID_STRING;
	showDeletedControl.ldctl_iscritical = FALSE;
	showDeletedControl.ldctl_value.bv_len = 0;
	showDeletedControl.ldctl_value.bv_val = NULL;

	// Set timeout to 10 seconds
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	// Search for deleted objects using SHOW_DELETED control
	ldapErr = WLDAP32$ldap_search_ext_s(
		ld,
		searchDN,
		LDAP_SCOPE_ONELEVEL,
		"(isDeleted=TRUE)",
		attrs,
		0,
		controls,
		NULL,
		&timeout,
		1000,
		&res
	);

	if (ldapErr == LDAP_SUCCESS) {
		if (res) {
			LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
			if (entry) {
				internal_printf("[+] Found deleted object(s)\n");
				WLDAP32$ldap_msgfree(res);
				return TRUE;
			}
			WLDAP32$ldap_msgfree(res);
		}
		// Search succeeded but no entries
		internal_printf("[*] No deleted objects found (ADRB may be empty)\n");
		internal_printf("[*] Cannot determine access level. Typically requires Domain Admin or Enterprise Admin privileges.\n");
		return FALSE;
	}

	// Search failed - access denied
	internal_printf("[-] Deleted objects search failed (LDAP error: %lu)\n", ldapErr);
	internal_printf("[*] Typically requires Domain Admin or Enterprise Admin privileges to access ADRB.\n");
	return FALSE;
}


#ifdef BOF
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	if (!bofstart()) {
		return;
	}

	LDAP* ld = NULL;
	char* rootDN = NULL;
	BOOL hasAccess = FALSE;

	internal_printf("[*] Checking ADRB read access for current user...\n");

	ld = WLDAP32$ldap_init(NULL, LDAP_PORT);
	if (!ld) {
		internal_printf("[-] Failed to initialize LDAP\n");
		goto cleanup;
	}

	internal_printf("[+] LDAP initialized\n");

	if (WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
		internal_printf("[-] Failed to bind to LDAP\n");
		goto cleanup;
	}

	internal_printf("[+] LDAP bound successfully\n");

	if (!GetRootDN(ld, &rootDN)) {
		internal_printf("[-] Failed to get root DN\n");
		goto cleanup;
	}

	internal_printf("[+] Root DN: %s\n", rootDN);

	if (CheckDeletedObjectsAccess(ld, rootDN)) {
		hasAccess = TRUE;
	}

	internal_printf("\n");
	if (hasAccess) {
		internal_printf("[+] RESULT: User HAS read access to ADRB\n");
	} else {
		internal_printf("[-] RESULT: User does NOT have read access to ADRB\n");
	}

cleanup:
	if (rootDN) {
		intFree(rootDN);
	}
	if (ld) {
		WLDAP32$ldap_unbind(ld);
	}

	printoutput(TRUE);
};

#else

int main() {
	LDAP* ld = NULL;
	char* rootDN = NULL;
	BOOL hasAccess = FALSE;

	printf("[*] Checking ADRB read access for current user...\n");

	ld = WLDAP32$ldap_init(NULL, LDAP_PORT);
	if (!ld) {
		printf("[-] Failed to initialize LDAP\n");
		return 1;
	}

	printf("[+] LDAP initialized\n");

	if (WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
		printf("[-] Failed to bind to LDAP\n");
		WLDAP32$ldap_unbind(ld);
		return 1;
	}

	printf("[+] LDAP bound successfully\n");

	if (GetRootDN(ld, &rootDN)) {
		printf("[+] Root DN: %s\n", rootDN);

		if (CheckDeletedObjectsAccess(ld, rootDN)) {
			hasAccess = TRUE;
		}

		printf("\n");
		if (hasAccess) {
			printf("[+] RESULT: User HAS read access to ADRB\n");
		} else {
			printf("[-] RESULT: User does NOT have read access to ADRB\n");
		}

		free(rootDN);
	}

	WLDAP32$ldap_unbind(ld);
	return 0;
}

#endif