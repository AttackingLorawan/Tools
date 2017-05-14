#include <stdio.h>
#include <ctype.h>


int convertHexChar(char c)
{
  int to_ret = -1;
  if ('0' <= c && c <= '9')
    to_ret = c - '0';
  if ('a' <= c && c <= 'f')
    to_ret = c - 'a' + 10;
  if ('A' <= c && c <= 'F')
    to_ret = c - 'A' + 10;
  return to_ret;
}


int unhexlify(char *hexstring, void* dest)
{
  unsigned char val;
  unsigned char *ptr;
  unsigned char low, high;
  int hexlen;
  int i;
  
  ptr = dest;
  hexlen = strlen(hexstring);
  
  for(i = 0; i < hexlen; i += 2)
    {
      high = convertHexChar(hexstring[i]);      
      low = convertHexChar(hexstring[i+1]);
      if (high == -1 || low == -1)
	return 0;
      val = (high << 4) + low;
      *ptr++ = val;
    }
}


#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif

void hexdump(void *mem, unsigned int len)
{
  unsigned int i, j;

  for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
      /* print offset */
      if(i % HEXDUMP_COLS == 0)
	{
	  printf("0x%06x: ", i);
	}

      /* print hex data */
      if(i < len)
	{
	  printf("%02x ", 0xFF & ((char*)mem)[i]);
	}
      else /* end of block, just aligning for ASCII dump */
	{
	  printf("   ");
	}
      /* print ASCII dump */
      if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
	{
	  for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
	    {
	      if(j >= len) /* end of block, not really printing */
		{
		  putchar(' ');
		}
	      else if(isprint(((char*)mem)[j])) /* printable char */
		{
		  putchar(0xFF & ((char*)mem)[j]);
		}
	      else /* other char */
		{
		  putchar('.');
		}
	    }
	  putchar('\n');
	}
    }
}
 
