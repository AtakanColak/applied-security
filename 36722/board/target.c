/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "target.h"

//1. INSERT RANDOM LOAD TO SUBBYTES
//2. RANDOM START POINT SBOX
//3. 

typedef uint8_t aes_gf28_t;
typedef uint32_t aes_gf28_word;
typedef uint8_t gf28_k;

int ghost = 0;

aes_gf28_t AES_RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
aes_gf28_t sbox_table[256];


#define NB 4
#define NR 9

#define READ_BYTE (scale_uart_rd(SCALE_UART_MODE_BLOCKING))
#define WRITE_BYTE(c) (scale_uart_wr(SCALE_UART_MODE_BLOCKING, c))

#define AES_ENC_RND_ROW_STEP(a, b, c, d, e, f, g, h) \
  {                                                  \
    aes_gf28_t __a1 = s[a];                          \
    aes_gf28_t __b1 = s[b];                          \
    aes_gf28_t __c1 = s[c];                          \
    aes_gf28_t __d1 = s[d];                          \
    s[e] = __a1;                                     \
    s[f] = __b1;                                     \
    s[g] = __c1;                                     \
    s[h] = __d1;                                     \
  }

#define AES_ENC_RND_MIX_STEP(a, b, c, d)   \
  {                                        \
    aes_gf28_t __a1 = s[a];                \
    aes_gf28_t __b1 = s[b];                \
    aes_gf28_t __c1 = s[c];                \
    aes_gf28_t __d1 = s[d];                \
                                           \
    aes_gf28_t __a2 = aes_gf28_mulx(__a1); \
    aes_gf28_t __b2 = aes_gf28_mulx(__b1); \
    aes_gf28_t __c2 = aes_gf28_mulx(__c1); \
    aes_gf28_t __d2 = aes_gf28_mulx(__d1); \
                                           \
    aes_gf28_t __a3 = __a1 ^ __a2;         \
    aes_gf28_t __b3 = __b1 ^ __b2;         \
    aes_gf28_t __c3 = __c1 ^ __c2;         \
    aes_gf28_t __d3 = __d1 ^ __d2;         \
                                           \
    s[a] = __a2 ^ __b3 ^ __c1 ^ __d1;      \
    s[b] = __a1 ^ __b2 ^ __c3 ^ __d1;      \
    s[c] = __a1 ^ __b1 ^ __c2 ^ __d3;      \
    s[d] = __a3 ^ __b1 ^ __c1 ^ __d2;      \
  }

void octetstr_wr(const uint8_t *x, int n_x);

char * hex_string = "0123456789ABCDEF";

uint8_t htoi(char c) {
  for(uint8_t i = 0; i < 16; ++i)
    if(hex_string[i] == c) return i;
  return 16;
}

char itoh(uint8_t n)
{
  if ( n < 16) return hex_string[n];
  return 'Z';
}

void pfs(char * s) {
  for(int i = 0; i < strlen(s); ++i) {
    WRITE_BYTE(s[i]);
  }
}

/** Read  an octet string (or sequence of bytes) from the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[out] r the destination octet string read
  * \return       the number of octets read
  */


int _octetstr_rd( uint8_t* r, int n_r, char* x ) {
  //Convert all hex chars to integers
  int size = (htoi(x[0]) << 4) | htoi(x[1]);

  for (int i = 0; i < size; ++i) {
    r[i] = (htoi(x[2*i + 3]) << 4) | htoi(x[2*i + 4]);
  }

  // pfs("Received ");
  // octetstr_wr(r, size);
  return size;
}

int octetstr_rd( uint8_t* r, int n_r) {
  char x[ 2 + 1 + 2 * ( n_r ) + 1 ]; // 2-char length, 1-char colon, 2*n_r-char data, 1-char terminator
//   if(!ghost) ghost = 1;
//   else {
//     uint8_t byteghost = READ_BYTE;
//     WRITE_BYTE(itoh(byteghost >> 4));
//     WRITE_BYTE(itoh(byteghost & 0x0F));
//   WRITE_BYTE('\n');
//   ghost = 0;
// }
  for( int i = 0; true; i++ ) {
    x[ i ] = READ_BYTE;
    if( x[ i ] == '\x0D' ) {
      x[ i ] = '\x00'; break;
    }
  }

  return _octetstr_rd( r, n_r, x );
}



/** Write an octet string (or sequence of bytes) to   the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[in]  r the source      octet string written
  * \param[in]  n the number of octets written
  */

void octetstr_wr(const uint8_t *x, int n_x)
{
  char s[ 2 + 1 + 2 * ( n_x ) + 1 ];
  s[0] = itoh(n_x >> 4);
  s[1] = itoh(n_x & 0x0F);
  s[2] = ':';

  for (int i = 0; i < n_x; ++i) {
    s[2*i + 3] = itoh(x[i] >> 4);
    s[2*i + 4] = itoh(x[i] & 0x0F);
  }
  s[2 * n_x + 3] = '\x00';
  pfs(s);
  WRITE_BYTE('\x0D');
  return;
}

aes_gf28_t aes_gf28_mulx(aes_gf28_t a)
{
  if (a & 0x80)
    return 0x1B ^ (a << 1);
  else
    return (a << 1);
}

//Works
aes_gf28_t aes_gf28_mul(aes_gf28_t a, aes_gf28_t b)
{
  aes_gf28_t t = 0;
  for (int i = 7; i >= 0; i--)
  {
    t = aes_gf28_mulx(t);
    if ((b >> i) & 1)
      t ^= a;
  }
  return t;
}

//Works
aes_gf28_t aes_gf28_inv(aes_gf28_t a)
{
  //Fermats little theorem states that a ^ -1 is a ^ (q-2)
  aes_gf28_t t_0 = aes_gf28_mul(a, a);   //a^2
  aes_gf28_t t_1 = aes_gf28_mul(t_0, a); //a^3
  t_0 = aes_gf28_mul(t_0, t_0);          //a^4
  t_1 = aes_gf28_mul(t_1, t_0);          //a^7
  t_0 = aes_gf28_mul(t_0, t_0);          //a^8
  t_0 = aes_gf28_mul(t_1, t_0);          //a^15
  t_0 = aes_gf28_mul(t_0, t_0);          //a^30
  t_0 = aes_gf28_mul(t_0, t_0);          //a^60
  t_1 = aes_gf28_mul(t_1, t_0);          //a^67
  t_0 = aes_gf28_mul(t_1, t_0);          //a^127
  t_0 = aes_gf28_mul(t_0, t_0);          //a^254
  return t_0;
}

//Works
aes_gf28_t aes_enc_sbox(aes_gf28_t a)
{
  a = aes_gf28_inv(a);

  a = (0x63) ^
      (a) ^
      (a << 1) ^
      (a >> 7) ^
      (a << 2) ^
      (a >> 6) ^
      (a << 3) ^
      (a >> 5) ^
      (a << 4) ^
      (a >> 4); // Left Bitwise Circular Shift
  // because left bitwise shift isn't cool enough
  return a;
}

void compute_sbox_table() {
  for(int b = 0; b < 256; ++b)
      sbox_table[b] = aes_enc_sbox(b);
}

//Works
void sub_word(aes_gf28_t *src)
{
  for (int i = 0; i < 4; ++i)
    src[i] = sbox_table[src[i]];
}

//Works
void rot_word(aes_gf28_t *src)
{
  aes_gf28_t temp = src[0];
  for (int i = 0; i < 3; ++i)
    src[i] = src[i + 1];
  src[3] = temp;
}

//Nk number of 32 bit word compromising Cipher Key

//Works
void aes_enc_exp_step(aes_gf28_t *rk, aes_gf28_t rc)
{
  aes_gf28_t temp[4];

  int i = 0;
  while (i < 4)
  {

    for (int j = 0; j < 4; ++j)
      temp[j] = rk[4 * ((i + 3) % 4) + j];

    if (i == 0)
    {
      rot_word(temp);
      sub_word(temp);
      temp[0] ^= rc;
    }

    for (int j = 0; j < 4; ++j)
      rk[4 * i + j] ^= temp[j];

    i = i + 1;
  }
}

void aes_enc_rnd_key(aes_gf28_t *s, const aes_gf28_t *rk)
{
  for (int i = 0; i < 16; ++i)
    s[i] = s[i] ^ rk[i];
}

void aes_enc_rnd_sub(aes_gf28_t *s)
{
  for (int i = 0; i < 16; ++i)
    s[i] = sbox_table[s[i]];
}

void aes_enc_rnd_row(aes_gf28_t * s) {
  AES_ENC_RND_ROW_STEP(1,5,9,13,13,1,5,9);
  AES_ENC_RND_ROW_STEP(2,6,10,14,10,14,2,6);
  AES_ENC_RND_ROW_STEP(3,7,11,15,7,11,15,3);
}

void aes_enc_rnd_mix(aes_gf28_t * s) {
  AES_ENC_RND_MIX_STEP(0, 1, 2, 3);
  AES_ENC_RND_MIX_STEP(4, 5, 6, 7);
  AES_ENC_RND_MIX_STEP(8, 9, 10, 11);
  AES_ENC_RND_MIX_STEP(12, 13, 14, 15);
}


/** Initialise an AES-128 encryption, e.g., expand the cipher key k into round
  * keys, or perform randomised pre-computation in support of a countermeasure;
  * this can be left blank if no such initialisation is required, because the
  * same k and r will be passed as input to the encryption itself.
  *
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes_init(const uint8_t *k, const uint8_t *r)
{
  return;
}

/** Perform    an AES-128 encryption of a plaintext m under a cipher key k, to
  * yield the corresponding ciphertext c.
  *
  * \param[out] c   an   AES-128 ciphertext
  * \param[in]  m   an   AES-128 plaintext
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes(uint8_t *c, const uint8_t *m, const uint8_t *k, const uint8_t *r)
{
  aes_gf28_t rk[16], s[16];

  //aes_gf28_t * rcp = AES_RC;
  aes_gf28_t * rkp = rk;

  memcpy(s,   m, sizeof(aes_gf28_t) * 16);
  memcpy(rkp, k, sizeof(aes_gf28_t) * 16);

  // 1 initial round
  aes_enc_rnd_key(s, rkp);
  // NR - 1 iterated rounds
  for (int i = 1; i < 10; ++i) {
    aes_enc_rnd_sub(s);
    aes_enc_rnd_row(s);
    aes_enc_rnd_mix(s);
    aes_enc_exp_step(rkp, AES_RC[i - 1]);
    aes_enc_rnd_key(s, rkp);
  }
  // 1 final round
  aes_enc_rnd_sub(s);
  aes_enc_rnd_row(s);
  aes_enc_exp_step(rkp, AES_RC[9]);
  aes_enc_rnd_key(s, rkp);

  memcpy(c, s, sizeof(aes_gf28_t) * 16);
  return;
}

/** Initialise the SCALE development board, then loop indefinitely, reading a
  * command then processing it:
  *
  * 1. If command is inspect, then
  *
  *    - write the SIZEOF_BLK parameter,
  *      i.e., number of bytes in an  AES-128 plaintext  m, or ciphertext c,
  *      to the UART,
  *    - write the SIZEOF_KEY parameter,
  *      i.e., number of bytes in an  AES-128 cipher key k,
  *      to the UART,
  *    - write the SIZEOF_RND parameter,
  *      i.e., number of bytes in the         randomness r.
  *      to the UART.
  *
  * 2. If command is encrypt, then
  *
  *    - read  an   AES-128 plaintext  m from the UART,
  *    - read  some         randomness r from the UART,
  *    - initalise the encryption,
  *    - set the trigger signal to 1,
  *    - execute   the encryption, producing the ciphertext
  *
  *      c = AES-128.Enc( m, k )
  *
  *      using the hard-coded cipher key k plus randomness r if/when need be,
  *    - set the trigger signal to 0,
  *    - write an   AES-128 ciphertext c to   the UART.
  */

int main(int argc, char *argv[])
{
  compute_sbox_table();
  if (!scale_init(&SCALE_CONF))
  {
    return -1;
  }

  uint8_t cmd[1], c[SIZEOF_BLK], m[SIZEOF_BLK], k[SIZEOF_KEY] = {0xA1, 0xA2, 0xD5, 0x52, 0x76, 0x67, 0x29, 0xA6, 0xF0, 0xED, 0x1E, 0xD8, 0xD8, 0x02, 0xEB, 0xFF}, r[SIZEOF_RND];
  uint8_t k1[SIZEOF_KEY] = {0xCD,0x97,0x16,0xE9,0x5B,0x42,0xDD,0x48,0x69,0x77,0x2A,0x34,0x6A,0x7F,0x58,0x13};

  while (true)
  {
    // pfs("\n");
    int result = octetstr_rd(cmd, 1);
    if (1 != result)
    {
      // pfs("READ ERROR");
      // WRITE_BYTE(itoh(result));
      break;
    }
    switch (cmd[0])
    {
    case COMMAND_INSPECT:
    {
      scale_gpio_wr(SCALE_GPIO_PIN_TRG, true);
      uint8_t t = SIZEOF_BLK;
      octetstr_wr(&t, 1);
      t = SIZEOF_KEY;
      octetstr_wr(&t, 1);
      t = SIZEOF_RND;
      octetstr_wr(&t, 1);

      break;
    }
    case COMMAND_ENCRYPT:
    {
      if (SIZEOF_BLK != octetstr_rd(m, SIZEOF_BLK))
      {
        break;
      }
      if (SIZEOF_RND != octetstr_rd(r, SIZEOF_RND))
      {
        break;
      }

      aes_init(k, r);

      scale_gpio_wr(SCALE_GPIO_PIN_TRG, true);
      aes(c, m, k1, r);
      scale_gpio_wr(SCALE_GPIO_PIN_TRG, false);

      octetstr_wr(c, SIZEOF_BLK);

      break;
    }
    default:
    {
      break;
    }
    }
  }

  return 0;
}

// int octetstr_rd(uint8_t *r, int n_r)
// {
//   if (ghost != 0) READ_BYTE;
//   else ghost = 1;
//   uint8_t size = read_hex_byte();
//   char semi_colon = READ_BYTE;
//
//   if (semi_colon != ':') {
//     //WRITE_BYTE(semi_colon);
//     return -1;
//   }
//   if (size > n_r) {
//     //WRITE_BYTE(size + '0');
//     return -1;
//   }
//   for (int i = 0; i < size; ++i)
//     r[i] = read_hex_byte();
//
//   //EOL
//   semi_colon = READ_BYTE;
//
//   pfs("Read: ");
//   octetstr_wr(r,size);
//   return size;
// }
