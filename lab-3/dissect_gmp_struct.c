/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
 * which can be found via http://creativecommons.org (and should be included as 
 * LICENSE.txt within the associated archive or repository).
 */

#include "dissect_gmp_struct.h"

int main( int argc, char* argv[] ) {
  mpz_t x;

  mpz_init( x );

  if( 1 != gmp_scanf( "%Zd", x ) ) {
    abort();
  }

  size_t n = abs( x->_mp_size );

  mp_limb_t* t = x->_mp_d;



  for( int i = 0; i < n; i++ ) {
    if( i != 0 ) {
      gmp_printf( "+" );
    }

    gmp_printf( "%llu*(2^(64))^(%d)", t[ i ], i );
  }

  gmp_printf( "\n" );

  mpz_clear( x );

  return 0;
}

