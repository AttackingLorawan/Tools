#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>


#include "semtech_aes.h"
#define LORAMAC_PHY_MAXPAYLOAD                      255

void hexdump(void *mem, unsigned int len);


static uint8_t LoRaMacRxPayload[LORAMAC_PHY_MAXPAYLOAD];

// 2008550515b2154fcca6d24d2025efddd4


/*!                                                                                                                      
 * AES encryption/decryption cipher network session key                                                                  
 */
static uint8_t LoRaMacNwkSKey[] =
  {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

/*!                                                                                                                      
 * AES encryption/decryption cipher application session key                                                              
 */
static uint8_t LoRaMacAppSKey[] =
  {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };


static aes_context AesContext;

/*!                                                                                                                      
 * Network ID ( 3 bytes )                                                                                                
 */
static uint32_t LoRaMacNetID;

/*!                                                                                                                      
 * Mote Address                                                                                                          
 */
static uint32_t LoRaMacDevAddr;



int unhexlify(char *hexstring, void* dest);
void LoRaMacJoinDecrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *decBuffer );
void LoRaMacJoinComputeSKeys( const uint8_t *key, const uint8_t *appNonce, uint16_t devNonce, uint8_t *nwkSKey, uint8_t *appSKey );

int main(int ac, char **av)
{
  char appkey[16];
  char payload[255];
  uint16_t devnonce_rev;
  uint16_t devnonce;
  int payload_len;
  char nonce[8];
  int size;

  if (ac < 4)
    {
      printf("Usage: %s appkey devnonce payload\n", av[0]);
      printf("-- payload size must be 35 bytes.\n");
      printf("IE : %s 000102030405060708090a0b0c0d0e0f aabb 2008550515b2154fcca6d24d2025efddd4\n", av[0]);
      exit(-1);
    }
  if (strlen(av[1]) != 32) { printf("wrong appkey size\n"); exit(-1); }
  unhexlify(av[1], appkey);
  if (strlen(av[2]) != 4) { printf("wrong devnonce size\n"); exit(-1); }
  unhexlify(av[2], &devnonce_rev);
  devnonce  = htons(devnonce_rev);
  //if (strlen(av[3]) != 34) { printf("wrong payload size\n"); exit(-1); }
  unhexlify(av[3], payload);
  size = strlen(av[3]) / 2;

  //printf("devnonce: %04x\n", devnonce);
  //hexdump(appkey, 16);
  
  //printf("--- Calling joindecrypt\n");
  LoRaMacJoinDecrypt( payload + 1, size - 1, appkey, LoRaMacRxPayload + 1 );
  LoRaMacRxPayload[0] = 0x20;


  //hexdump(LoRaMacRxPayload+1, size-1);

  LoRaMacNetID = ( uint32_t )LoRaMacRxPayload[4];
  LoRaMacNetID |= ( ( uint32_t )LoRaMacRxPayload[5] << 8 );
  LoRaMacNetID |= ( ( uint32_t )LoRaMacRxPayload[6] << 16 );

  LoRaMacDevAddr = ( uint32_t )LoRaMacRxPayload[7];
  LoRaMacDevAddr |= ( ( uint32_t )LoRaMacRxPayload[8] << 8 );
  LoRaMacDevAddr |= ( ( uint32_t )LoRaMacRxPayload[9] << 16 );
  LoRaMacDevAddr |= ( ( uint32_t )LoRaMacRxPayload[10] << 24 );
  
  printf("NetID: %08x\n", LoRaMacNetID);
  printf("DevAddr: %08x\n", LoRaMacDevAddr);
  
  printf("---- ComputingSkeys\n");
  LoRaMacJoinComputeSKeys( appkey, LoRaMacRxPayload + 1, devnonce, LoRaMacNwkSKey,
			   LoRaMacAppSKey );

  printf("NwkSkey: ");
  for (size = 0; size < 16; size++)
    printf("%02x", LoRaMacNwkSKey[size]);
  printf("\n");
  printf("APPSkey: ");
  for (size = 0; size < 16; size++)
    printf("%02x", LoRaMacAppSKey[size]);
  printf("\n");

  
  
}


void LoRaMacJoinDecrypt( const uint8_t *buffer, uint16_t size, const uint8_t *key, uint8_t *decBuffer )
{
  memset( AesContext.ksch, '\0', 240 );
  aes_set_key( key, 16, &AesContext );
  aes_encrypt( buffer, decBuffer, &AesContext );
  // Check if optional CFList is included
  if( size >= 16 )
    {
      aes_encrypt( buffer + 16, decBuffer + 16, &AesContext );
    }
}



void LoRaMacJoinComputeSKeys( const uint8_t *key, const uint8_t *appNonce, uint16_t devNonce, uint8_t *nwkSKey, uint8_t *appSKey )
{
  uint8_t nonce[16];
  uint8_t *pDevNonce = ( uint8_t * )&devNonce;

  memset( AesContext.ksch, '\0', 240 );
  aes_set_key( key, 16, &AesContext );

  memset( nonce, 0, sizeof( nonce ) );
  nonce[0] = 0x01;
  memcpy( nonce + 1, appNonce, 6 );
  memcpy( nonce + 7, pDevNonce, 2 );
  aes_encrypt( nonce, nwkSKey, &AesContext );

  memset( nonce, 0, sizeof( nonce ) );
  nonce[0] = 0x02;
  memcpy( nonce + 1, appNonce, 6 );
  memcpy( nonce + 7, pDevNonce, 2 );
  aes_encrypt( nonce, appSKey, &AesContext );
}

