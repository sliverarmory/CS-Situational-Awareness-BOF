#include <windows.h>
#include "bofdefs.h"
#include "base.c"

typedef struct {
	char cn[256];
	char sam[256];
	char type[64];
	char whenDeleted[64];
	char whenChanged[64];
	char dn[512];
	char lastKnownParent[512];
	char objectSid[256];
	char description[512];
	char servicePrincipalNames[1024];
	char delegateTo[1024];
	char members[2048];
	int adminCount;
	int userAccountControl;
	BOOL hasManagedPassword;
} DELETED_OBJECT;

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

// Parse deleted DN to extract CN and deletion GUID
// Format: CN=name\0ADEL:guid,CN=Deleted Objects,...
void ParseDeletedDN(char* dn, char* cn_out, int cn_len) {
	MSVCRT$memset(cn_out, 0, cn_len);

	char* first_comma = MSVCRT$strchr(dn, ',');
	if (!first_comma) {
		MSVCRT$strcpy(cn_out, dn);
		return;
	}

	int cn_part_len = first_comma - dn;
	if (cn_part_len >= cn_len) cn_part_len = cn_len - 1;

	// Copy CN part
	MSVCRT$memcpy(cn_out, dn, cn_part_len);
	cn_out[cn_part_len] = '\0';

	// Remove "CN=" prefix
	if (MSVCRT$strncmp(cn_out, "CN=", 3) == 0) {
		char temp[256] = {0};
		MSVCRT$strcpy(temp, cn_out + 3);
		MSVCRT$strcpy(cn_out, temp);
	}

	// Handle deleted marker - truncate at backslash or ADEL marker
	char* backslash = MSVCRT$strchr(cn_out, '\\');
	if (backslash) {
		*backslash = '\0';
	} else {
		char* adel_marker = MSVCRT$strstr(cn_out, "ADEL:");
		if (adel_marker && adel_marker > cn_out) {
			*(adel_marker - 1) = '\0';
		}
	}
}

// Get object type from objectClass attribute
void ExtractObjectType(LDAP* ld, LDAPMessage* entry, char* type_out, int type_len) {
	PCHAR* values = WLDAP32$ldap_get_values(ld, entry, "objectClass");
	MSVCRT$strcpy(type_out, "unknown");

	if (values) {
		// Check for specific types (check in reverse order of specificity)
		for (int i = 0; values[i] != NULL; i++) {
			if (MSVCRT$strcmp(values[i], "computer") == 0) {
				MSVCRT$strcpy(type_out, "computer");
				break;
			}
			if (MSVCRT$strcmp(values[i], "user") == 0) {
				MSVCRT$strcpy(type_out, "user");
			}
			if (MSVCRT$strcmp(values[i], "group") == 0) {
				MSVCRT$strcpy(type_out, "group");
				break;
			}
		}
		WLDAP32$ldap_value_free(values);
	}
}

// Get string value from entry
void GetStringValue(LDAP* ld, LDAPMessage* entry, const char* attr, char* value_out, int value_len) {
	MSVCRT$memset(value_out, 0, value_len);
	PCHAR* values = WLDAP32$ldap_get_values(ld, entry, (PSTR)attr);
	if (values && values[0]) {
		int len = MSVCRT$strlen(values[0]);
		if (len >= value_len) len = value_len - 1;
		MSVCRT$memcpy(value_out, values[0], len);
		value_out[len] = '\0';
		WLDAP32$ldap_value_free(values);
	}
}

// Get integer value from entry
int GetIntValue(LDAP* ld, LDAPMessage* entry, const char* attr) {
	PCHAR* values = WLDAP32$ldap_get_values(ld, entry, (PSTR)attr);
	if (values && values[0]) {
		int val = 0;
		for (char* p = values[0]; *p; p++) {
			if (*p >= '0' && *p <= '9') {
				val = val * 10 + (*p - '0');
			} else {
				break;
			}
		}
		WLDAP32$ldap_value_free(values);
		return val;
	}
	return 0;
}

// Convert binary SID to string format (S-1-5-21-...)
void ConvertSIDToString(unsigned char* sid, int len, char* sid_str, int sid_str_len) {
	MSVCRT$memset(sid_str, 0, sid_str_len);
	if (len < 8) {
		MSVCRT$strcpy(sid_str, "invalid");
		return;
	}

	unsigned char revision = sid[0];
	unsigned char sub_auth_count = sid[1];
	unsigned long long authority = 0;

	// Read authority (6 bytes, big-endian)
	for (int i = 0; i < 6; i++) {
		authority = (authority << 8) | sid[2 + i];
	}

	int offset = 0;
	offset += MSVCRT$sprintf(sid_str + offset, "S-%u-%llu", revision, authority);

	// Read sub-authorities (4 bytes each, little-endian)
	int sub_auth_offset = 8;
	for (int i = 0; i < sub_auth_count && sub_auth_offset + 4 <= len; i++) {
		unsigned long sub_auth = sid[sub_auth_offset] |
								(sid[sub_auth_offset + 1] << 8) |
								(sid[sub_auth_offset + 2] << 16) |
								(sid[sub_auth_offset + 3] << 24);
		offset += MSVCRT$sprintf(sid_str + offset, "-%lu", sub_auth);
		sub_auth_offset += 4;
	}
}

// Get binary values and concatenate as strings (for multivalued attrs)
void GetStringValues(LDAP* ld, LDAPMessage* entry, const char* attr, char* values_out, int values_len) {
	MSVCRT$memset(values_out, 0, values_len);
	PCHAR* values = WLDAP32$ldap_get_values(ld, entry, (PSTR)attr);
	if (values) {
		int offset = 0;
		for (int i = 0; values[i] != NULL && offset < values_len - 1; i++) {
			if (i > 0 && offset < values_len - 2) {
				values_out[offset++] = ';';
				values_out[offset++] = ' ';
			}
			int len = MSVCRT$strlen(values[i]);
			if (offset + len > values_len - 1) {
				len = values_len - 1 - offset;
			}
			MSVCRT$memcpy(values_out + offset, values[i], len);
			offset += len;
		}
		values_out[offset] = '\0';
		WLDAP32$ldap_value_free(values);
	}
}

// Get binary attribute values
struct berval** GetBinaryValues(LDAP* ld, LDAPMessage* entry, const char* attr) {
	return WLDAP32$ldap_get_values_lenA(ld, entry, (PSTR)attr);
}

// Check if binary attribute exists and is not empty
BOOL HasBinaryAttribute(LDAP* ld, LDAPMessage* entry, const char* attr) {
	struct berval** values = GetBinaryValues(ld, entry, attr);
	if (values && values[0] && values[0]->bv_len > 0) {
		WLDAP32$ldap_value_free_len(values);
		return TRUE;
	}
	return FALSE;
}

ULONG ListDeletedObjects(LDAP* ld, char* rootDN) {
	LDAPMessage* res = NULL;
	char searchDN[512] = {0};
	char* attrs[] = {
		"sAMAccountName", "objectClass", "objectSid", "sIDHistory",
		"whenDeleted", "whenChanged", "lastKnownParent",
		"userAccountControl", "adminCount", "description",
		"servicePrincipalName", "msDS-AllowedToDelegateTo", "member",
		"msDS-ManagedPasswordId", NULL
	};
	ULONG ldapErr = 0;
	LDAP_TIMEVAL timeout = {0};
	LDAPControlA showDeletedControl = {0};
	PLDAPControlA controls[] = { &showDeletedControl, NULL };
	ULONG entryCount = 0;

	MSVCRT$sprintf(searchDN, "CN=Deleted Objects,%s", rootDN);
	internal_printf("\n[*] Searching deleted objects in: %s\n\n", searchDN);

	// Setup SHOW_DELETED control
	showDeletedControl.ldctl_oid = (PCHAR)LDAP_CONTROL_SHOW_DELETED_OID_STRING;
	showDeletedControl.ldctl_iscritical = FALSE;
	showDeletedControl.ldctl_value.bv_len = 0;
	showDeletedControl.ldctl_value.bv_val = NULL;

	// Set timeout to 10 seconds
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	// Search for deleted objects
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

	if (ldapErr != LDAP_SUCCESS) {
		internal_printf("[-] Search failed (LDAP error: %lu)\n", ldapErr);
		internal_printf("[*] Typically requires Domain Admin or Enterprise Admin privileges.\n");
		return 0;
	}

	if (!res) {
		internal_printf("[*] No results returned\n");
		internal_printf("[*] Typically requires Domain Admin or Enterprise Admin privileges.\n");
		return 0;
	}

	entryCount = WLDAP32$ldap_count_entries(ld, res);

	if (entryCount == 0) {
		internal_printf("[*] No deleted objects found!\n");
		internal_printf("[*] ADRB is empty or the user does not have the required privileges to read it!\n");
		WLDAP32$ldap_msgfree(res);
		return 0;
	}

	internal_printf("[+] Found %lu deleted object(s)\n\n", entryCount);

	// Allocate large buffers once before loop to avoid stack overflow
	DELETED_OBJECT* obj = (DELETED_OBJECT*)intAlloc(sizeof(DELETED_OBJECT));
	if (!obj) {
		internal_printf("[-] Memory allocation failed\n");
		WLDAP32$ldap_msgfree(res);
		return 0;
	}

	LDAPMessage* entry = WLDAP32$ldap_first_entry(ld, res);
	ULONG displayed = 0;

	while (entry) {
		MSVCRT$memset(obj, 0, sizeof(DELETED_OBJECT));
		char* dnPtr = NULL;
		int i = 0;

		dnPtr = WLDAP32$ldap_get_dn(ld, entry);
		if (dnPtr) {
			ParseDeletedDN(dnPtr, obj->cn, sizeof(obj->cn));
			MSVCRT$strcpy(obj->dn, dnPtr);
			WLDAP32$ldap_memfree(dnPtr);
		}

		GetStringValue(ld, entry, "sAMAccountName", obj->sam, sizeof(obj->sam));
		ExtractObjectType(ld, entry, obj->type, sizeof(obj->type));
		GetStringValue(ld, entry, "whenDeleted", obj->whenDeleted, sizeof(obj->whenDeleted));
		GetStringValue(ld, entry, "whenChanged", obj->whenChanged, sizeof(obj->whenChanged));
		GetStringValue(ld, entry, "lastKnownParent", obj->lastKnownParent, sizeof(obj->lastKnownParent));
		GetStringValue(ld, entry, "description", obj->description, sizeof(obj->description));
		GetStringValues(ld, entry, "servicePrincipalName", obj->servicePrincipalNames, sizeof(obj->servicePrincipalNames));
		GetStringValues(ld, entry, "msDS-AllowedToDelegateTo", obj->delegateTo, sizeof(obj->delegateTo));
		GetStringValues(ld, entry, "member", obj->members, sizeof(obj->members));
		obj->adminCount = GetIntValue(ld, entry, "adminCount");
		obj->userAccountControl = GetIntValue(ld, entry, "userAccountControl");
		obj->hasManagedPassword = HasBinaryAttribute(ld, entry, "msDS-ManagedPasswordId");

		// Extract objectSid
		struct berval** sidValues = GetBinaryValues(ld, entry, "objectSid");
		if (sidValues && sidValues[0]) {
			ConvertSIDToString((unsigned char*)sidValues[0]->bv_val, sidValues[0]->bv_len, obj->objectSid, sizeof(obj->objectSid));
			WLDAP32$ldap_value_free_len(sidValues);
		}

		// Display object details
		internal_printf("\n[*] %s (%s)\n", obj->cn, obj->type);
		internal_printf("    DN                      : %s\n", obj->dn);

		if (obj->sam[0]) {
			internal_printf("    SAM                     : %s\n", obj->sam);
		}

		if (obj->objectSid[0]) {
			internal_printf("    ObjectSID               : %s\n", obj->objectSid);
		}

		// Check for security-relevant sIDHistory
		struct berval** sidHistoryValues = GetBinaryValues(ld, entry, "sIDHistory");
		if (sidHistoryValues) {
			for (i = 0; sidHistoryValues[i] != NULL; i++) {
				char sidHistStr[256] = {0};
				ConvertSIDToString((unsigned char*)sidHistoryValues[i]->bv_val, sidHistoryValues[i]->bv_len, sidHistStr, sizeof(sidHistStr));
				internal_printf("    sIDHistory              : %s\n", sidHistStr);
			}
			WLDAP32$ldap_value_free_len(sidHistoryValues);
		}

		if (obj->adminCount > 0) {
			internal_printf("    adminCount              : %d *** HIGH VALUE ***\n", obj->adminCount);
		}

		if (obj->servicePrincipalNames[0]) {
			internal_printf("    SPNs (Kerberoastable)   : %s\n", obj->servicePrincipalNames);
		}

		if (obj->delegateTo[0]) {
			internal_printf("    Constrained Delegation  : %s *** DELEGATION ***\n", obj->delegateTo);
		}

		if (obj->userAccountControl & 0x1000000) {
			internal_printf("    UAC Flag                : TRUSTED_TO_AUTH *** DELEGATION ***\n");
		}

		if (obj->description[0]) {
			internal_printf("    Description             : %s\n", obj->description);
		}

		if (obj->members[0]) {
			internal_printf("    Group Members           : %s\n", obj->members);
		}

		if (obj->hasManagedPassword) {
			internal_printf("    gMSA Password           : PRESENT *** OFFLINE RECOVERY ***\n");
		}

		if (obj->lastKnownParent[0]) {
			internal_printf("    Last Known Parent       : %s\n", obj->lastKnownParent);
		}

		if (obj->whenDeleted[0]) {
			internal_printf("    Deleted                 : %s\n", obj->whenDeleted);
		}

		if (obj->whenChanged[0]) {
			internal_printf("    Last Changed            : %s\n", obj->whenChanged);
		}

		displayed++;
		entry = WLDAP32$ldap_next_entry(ld, entry);
	}

	intFree(obj);

	internal_printf("\n[+] Displayed %lu objects\n\n", displayed);

	WLDAP32$ldap_msgfree(res);
	return displayed;
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
	ULONG result = 0;

	internal_printf("[*] Enumerating Active Directory Recycling Bin objects...\n");

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

	result = ListDeletedObjects(ld, rootDN);

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
	ULONG result = 0;

	printf("[*] Enumerating Active Directory Recycling Bin objects...\n");

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
		result = ListDeletedObjects(ld, rootDN);
		free(rootDN);
	}

	WLDAP32$ldap_unbind(ld);
	return 0;
}

#endif