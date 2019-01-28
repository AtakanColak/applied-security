/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
 * which can be found via http://creativecommons.org (and should be included as 
 * LICENSE.txt within the associated archive or repository).
 */

#include "ataes.h"

typedef uint8_t aes_gf28_t;

char* itob(uint8_t n) {
  char * str = malloc(sizeof(char) * 8);
  for (int i = 0; i < 8; ++i){
    str[7 - i] = ((n >> i) & 1) + '0';
  }
  return str;
}

aes_gf28_t aes_gf28_mulx(aes_gf28_t a) {
  if (a & 0x80) 
    return 0x1B ^ (a << 1);
  else
    return (a << 1);
}

aes_gf28_t aes_gf28_mul(aes_gf28_t a, aes_gf28_t b) {
  aes_gf28_t t = 0;
  for(int i = 7; i >= 0; --i) { 
    t = aes_gf28_mulx(t);
    if ((b>>i) & 1) 
      t ^= a;    
  }
}

aes_gf28_t aes_gf28_inv(aes_gf28_t a) {
  //Fermats little theorem states that a ^ -1 is a ^ (q-2)
  aes_gf28_t  t_0 = aes_gf28_mul(a,     a); //a^2
  aes_gf28_t  t_1 = aes_gf28_mul(t_0,   a); //a^3
              t_0 = aes_gf28_mul(t_0, t_0); //a^4
              t_1 = aes_gf28_mul(t_0, t_1); //a^7
              t_0 = aes_gf28_mul(t_0, t_0); //a^8
              t_0 = aes_gf28_mul(t_0, t_1); //a^15
              t_0 = aes_gf28_mul(t_0, t_0); //a^30
              t_0 = aes_gf28_mul(t_0, t_0); //a^60
              t_1 = aes_gf28_mul(t_0, t_1); //a^67
              t_0 = aes_gf28_mul(t_0, t_1); //a^127
              t_0 = aes_gf28_mul(t_0, t_0); //a^254
  return t_0;
}

aes_gf28_t sbox(aes_gf28_t a) {
  a = aes_gf28_inv(a);

  a = ( 0x63 ) ^ 
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



int main( int argc, char* argv[] ) {
  uint8_t k[ 16 ] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                      0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
  uint8_t m[ 16 ] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
                      0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
  uint8_t c[ 16 ] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
                      0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
  uint8_t t[ 16 ];

  //AES_KEY rk;

  //AES_set_encrypt_key( k, 128, &rk );
  //AES_encrypt( m, t, &rk );  

  //if( !memcmp( t, c, 16 * sizeof( uint8_t ) ) ) {
    //printf( "AES.Enc( k, m ) == c\n" );
  //}
  //else {
    //printf( "AES.Enc( k, m ) != c\n" );
  //}

  printf("\nTEST 1: xtime\n");
  printf("%s * x == %s\n", itob(127), itob(aes_gf28_mulx(127)));
  printf("%s * x == %s\n\n", itob(128), itob(aes_gf28_mulx(128)));


}
