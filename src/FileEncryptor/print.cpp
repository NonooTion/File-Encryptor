#include "print.h"
void print_hex(unsigned char str[], int str_len)
{
	for (int i = 0; i < str_len; i++)
		printf("%02x ", str[i]);
	printf("\n");
}