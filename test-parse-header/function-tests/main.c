#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "isendofhash.h"
#include "parse_sig.h"

int main () {

	printf("hello world\n");

	char *mystr = "Identity: abc.def.ghi;info=<https://www.web.cert>";
	int len_mystr = strlen(mystr);
	char *p = mystr; // "current" for traversing mystr
	char *end = mystr + len_mystr + 1; // pointer to \0 at end of mystr

	/*while (!isendofhash(p, end)) {
		printf("%c\n", *p);
		p++;
	}
	printf("is end of hash\n");*/
	parse_sig(p, end);


	// printf("%c\n", *mystr);
	// printf("%c\n", *(mystr+1));
	// printf("%c\n", *(mystr+2));
	// printf("%c\n", *(mystr+3)); // == '\0'

	// printf("%p\n", (mystr+3));
	// printf("%p\n", end);

	return 0;
}