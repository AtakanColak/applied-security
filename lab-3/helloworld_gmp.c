/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
 * which can be found via http://creativecommons.org (and should be included as 
 * LICENSE.txt within the associated archive or repository).
 */

#include "helloworld_gmp.h"

int main( int argc, char* argv[] ) {
  mpz_t r, x, y;

  mpz_init( r );
  mpz_init( x );
  mpz_init( y );

  if( 1 != gmp_scanf( "%Zd",  x ) ) {
    abort();
  }
  if( 1 != gmp_scanf( "%Zd",  y ) ) {
    abort();
  }

  mpz_add( r, x, y );

  gmp_printf( "%Zd\n", r );

  mpz_clear( r );
  mpz_clear( x );
  mpz_clear( y );

  return 0;
}
