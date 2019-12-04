#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "StrUtils.h"

char *str_replace( const char *string, const char *substr, const char *replacement ){
	  char *tok = NULL;
	  char *newstr = NULL;
	  char *oldstr = NULL;
	  char *head = NULL;
	 
	  /* if either substr or replacement is NULL, duplicate string a let caller handle it */
	  if ( substr == NULL || replacement == NULL ) return _strdup(string);
	  newstr = _strdup(string);
	  head = newstr;
	  while ( (tok = strstr ( head, substr ))){
		oldstr = newstr;
		newstr = (char*)malloc ( strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) + 1 );
		/*failed to alloc mem, free old string and return NULL */
		if ( newstr == NULL ){
		  free (oldstr);
		  return NULL;
		}
		memcpy ( newstr, oldstr, tok - oldstr );
		memcpy ( newstr + (tok - oldstr), replacement, strlen ( replacement ) );
		memcpy ( newstr + (tok - oldstr) + strlen( replacement ), tok + strlen ( substr ), strlen ( oldstr ) - strlen ( substr ) - ( tok - oldstr ) );
		memset ( newstr + strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) , 0, 1 );
		/* move back head right after the last replacement */
		head = newstr + (tok - oldstr) + strlen( replacement );
		free (oldstr);
	  }
	  return newstr;
}

void remove_all_chars(char* str, char c) {
	char *pr = str, *pw = str;
	while (*pr) {
		*pw = *pr++;
		pw += (*pw != c);
	}
	*pw = '\0';
}

inline char *uint8_t2char(uint8_t *a) {
	char* buffer2;
	int i;

	buffer2 = (char *)malloc(9);
	if (!buffer2)
		return NULL;

	buffer2[8] = 0;
	for (i = 0; i <= 7; i++)
		buffer2[7 - i] = (((*a) >> i) & (0x01)) + '0';

	puts(buffer2);

	return buffer2;
}

/* isAlphanum -- return true if the character is a letter, digit, underscore,
		dollar sign, or non-ASCII character.
*/
inline static int isAlphanum (int c) {
	return ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'Z') || c == '_' || c == '$' || c == '\\' || c > 126);
}