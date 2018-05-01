#include <stdio.h>
#include <string.h>

// input: "Identity: base64.base64.base64;info=<url>"
// puts base64 hash into hash variable; url into url variable
int parse_sig(char *p, char *end) {
	
	char hash[256];
	char* hash_start;
	int hash_len = 0;
	char url[256];
	char* url_start;
	int url_len = 0;

	// first 10 digits should be "Identity: "
	char identity[11];
	memcpy(identity, p, 10);
	identity[10] = '\0';
	if (strcmp(identity, "Identity: ")) {
		printf("no match\n");
		return -1;
	}

	// get base64 hash
	p += 10;
	hash_start = p;
	while (*p != ';') {
		p++;
		hash_len++;
	}
	memcpy(hash, hash_start, hash_len);
	hash[hash_len] = '\0';
	
	// get url
	p += 7; //skip "info=<"
	url_start = p;
	while (*p != '>') {
		p++;
		url_len++;
	}
	memcpy(url, url_start, url_len);
	url[url_len] = '\0';


	printf("hash: %s\n", hash);
	printf("url: %s\n", url);
	return 0;

}