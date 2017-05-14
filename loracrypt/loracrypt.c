#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include "semtech_aes.h"

#define APPKEY "0102030405060708090a0b0c0d0e0f10"

#define NWKSKEY "80808080808080808080808080808080"
#define APPSKEY "00000000000000000000000000000000"

//#define PAYLOAD "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP"
#define PAYLOAD "B"



void hexdump(void*, unsigned int);
void LoRaMacPayloadEncrypt( const uint8_t *buffer,
			    uint16_t size,
			    const uint8_t *key,
			    uint32_t address,
			    uint8_t dir,
			    uint32_t sequenceCounter,
			    uint8_t *encBuffer );

static aes_context AesContext;



void usage(char *argv)
{
  printf("Usage: %s payload appskey devaddr seqCount\n", argv);
  printf("   IE: %s DATATOSENDTOGATEWAY 00000000000000000000000000000000 f0401c2d 00ac\n", argv);
  exit(-1);
}

/*
int main2(int ac, char **av)
{
  unsigned char nwkskey[16];
  unsigned char appskey[16];
  LoRaMacJoinComputeSKeys( LoRaMacAppKey, LoRaMacRxPayload + 1, LoRaMacDevNonce, nwkskey, appskey);

}
*/


int main(int ac, char **argv)
{
  unsigned char nwkskey[16];
  unsigned char appskey[16];
  unsigned char tosend[512];
  
  unsigned int value;
  unsigned int devAddr = 0x06CB0589;
  unsigned int sequenceCounter = 0;
  /*
  if (unhexlify(argv[1], &value))
    printf("%08X\n", value);
  else
    printf("error\n");
  */
  unhexlify(APPSKEY, appskey);
  if (ac == 5)
    {
      unhexlify(argv[2], appskey);
      sscanf(argv[3], "%xl", &devAddr);
      //devAddr = ntohl(devAddr);
      sscanf(argv[4], "%xi", &sequenceCounter); 

    }
  else
    {
      usage(argv[0]);
    }
  // dir
  //address, dir, sequencecounter
  // dir : 0 uplink
  //       1 downlink
  printf("Dumping data with sequenceCounter = %04x\n", sequenceCounter);
  LoRaMacPayloadEncrypt(argv[1], strlen(argv[1]), appskey, devAddr,0,sequenceCounter, tosend);
  //printf("Dumping data with sequenceCounter = %04x\n", sequenceCounter);
  hexdump(tosend, 32);
  
  return (0);


}


/**
 *
 *
 *
 MACPHDR : 
*/
 

static uint8_t aBlock[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static uint8_t sBlock[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


void LoRaMacPayloadEncrypt( const uint8_t *buffer,
			    uint16_t size,
			    const uint8_t *key,
			    uint32_t address,
			    uint8_t dir,
			    uint32_t sequenceCounter,
			    uint8_t *encBuffer )
{
  uint16_t i;
  uint8_t bufferIndex = 0;
  uint16_t ctr = 1;

  memset( AesContext.ksch, 0, 240 );
  aes_set_key( key, 16, &AesContext );

  aBlock[5] = dir;

  aBlock[6] = ( address ) & 0xFF;
  aBlock[7] = ( address >> 8 ) & 0xFF;
  aBlock[8] = ( address >> 16 ) & 0xFF;
  aBlock[9] = ( address >> 24 ) & 0xFF;

  aBlock[10] = ( sequenceCounter ) & 0xFF;
  aBlock[11] = ( sequenceCounter >> 8 ) & 0xFF;
  aBlock[12] = ( sequenceCounter >> 16 ) & 0xFF;
  aBlock[13] = ( sequenceCounter >> 24 ) & 0xFF;

  while( size >= 16 )
    {
      aBlock[15] = ( ( ctr ) & 0xFF );
      ctr++;
      aes_encrypt( aBlock, sBlock, &AesContext );
      printf("Generated blk: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	     aBlock[0], aBlock[1], aBlock[2], aBlock[3],
	     aBlock[4], aBlock[0], aBlock[0], aBlock[7],
	     aBlock[8], aBlock[0], aBlock[10], aBlock[11],
	     aBlock[12], aBlock[13], sBlock[14], sBlock[15]);
      printf("Generated key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	     sBlock[0], sBlock[1], sBlock[2], sBlock[3],
	     sBlock[4], sBlock[0], sBlock[0], sBlock[7],
	     sBlock[8], sBlock[0], sBlock[10], sBlock[11],
	     sBlock[12], sBlock[13], sBlock[14], sBlock[15]);
      for( i = 0; i < 16; i++ )
	{
	  encBuffer[bufferIndex + i] = buffer[bufferIndex + i] ^ sBlock[i];
	}
      size -= 16;
      bufferIndex += 16;
    }

  if( size > 0 )
    {
      aBlock[15] = ( ( ctr ) & 0xFF );
      aes_encrypt( aBlock, sBlock, &AesContext );
      for( i = 0; i < size; i++ )
	{
	  encBuffer[bufferIndex + i] = buffer[bufferIndex + i] ^ sBlock[i];
	}
    }
}




