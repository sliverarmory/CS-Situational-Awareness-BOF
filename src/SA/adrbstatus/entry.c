#include <windows.h>
#include "bofdefs.h"
#include "base.c"

typedef struct {
	LDAP* ld;
	char* rootDN;
	BOOL adrbEnabled;
} ADRB_CONTEXT;

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

BOOL CheckADRBEnabled(LDAP* ld, char* rootDN) {
	LDAPMessage* res = NULL;
	char searchDN[512] = {0};
	char* attrs[] = { "msDS-EnabledFeatureBL", NULL };
	ULONG ldapErr = 0;

	// Check for Recycle Bin Feature in Configuration Partition
	MSVCRT$sprintf(searchDN, "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,%s", rootDN);
	internal_printf("[*] Searching: %s\n", searchDN);

	ldapErr = WLDAP32$ldap_search_s(ld, searchDN, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, &res);

	if (ldapErr == LDAP_SUCCESS) {
		if (res) {
			LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
			if (entry) {
				PCHAR* values = WLDAP32$ldap_get_values(ld, entry, "msDS-EnabledFeatureBL");
				if (values && values[0]) {
					internal_printf("[+] msDS-EnabledFeatureBL attribute found\n");
					internal_printf("[+] Active Directory Recycling Bin is ENABLED\n");
					WLDAP32$ldap_value_free(values);
					WLDAP32$ldap_msgfree(res);
					return TRUE;
				}
				if (values) WLDAP32$ldap_value_free(values);
			}
			WLDAP32$ldap_msgfree(res);
		}
	}

	internal_printf("[-] Recycle Bin Feature not found or attribute missing\n");
	internal_printf("[-] Active Directory Recycling Bin is DISABLED\n");
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

	internal_printf("[*] Checking Active Directory Recycling Bin Status...\n");

	// Connect to LDAP server
	ld = WLDAP32$ldap_init(NULL, LDAP_PORT);
	if (!ld) {
		internal_printf("[-] Failed to initialize LDAP\n");
		goto cleanup;
	}

	internal_printf("[+] LDAP initialized\n");

	// Bind to LDAP using current user's credentials (Negotiate/GSSAPI)
	if (WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
		internal_printf("[-] Failed to bind to LDAP with negotiate auth\n");
		goto cleanup;
	}

	internal_printf("[+] LDAP bound successfully (with current user credentials)\n");

	// Get root DN
	if (!GetRootDN(ld, &rootDN)) {
		internal_printf("[-] Failed to get root DN\n");
		goto cleanup;
	}

	internal_printf("[+] Root DN: %s\n", rootDN);

	// Check ADRB
	CheckADRBEnabled(ld, rootDN);

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

	printf("[*] Checking Active Directory Recycling Bin Status...\n");

	ld = WLDAP32$ldap_init(NULL, LDAP_PORT);
	if (!ld) {
		printf("[-] Failed to initialize LDAP\n");
		return 1;
	}

	printf("[+] LDAP initialized\n");

	if (WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
		printf("[-] Failed to bind to LDAP with negotiate auth\n");
		WLDAP32$ldap_unbind(ld);
		return 1;
	}

	printf("[+] LDAP bound successfully (with current user credentials)\n");

	if (GetRootDN(ld, &rootDN)) {
		printf("[+] Root DN: %s\n", rootDN);
		if (CheckADRBEnabled(ld, rootDN)) {
			printf("[+] ADRB is ENABLED\n");
		} else {
			printf("[-] ADRB is DISABLED\n");
		}
		free(rootDN);
	}

	WLDAP32$ldap_unbind(ld);
	return 0;
}

#endif
