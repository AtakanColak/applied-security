/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
 * which can be found via http://creativecommons.org (and should be included as 
 * LICENSE.txt within the associated archive or repository).
 */

#include "helloworld_libc.h"

int main( int argc, char* argv[] ) {
  int   r, x, y;





  if( 1 !=     scanf(  "%d", &x ) ) {
    abort();
  }
  if( 1 !=     scanf(  "%d", &y ) ) {
    abort();
  }

  r = x + y;

      printf(  "%d\n", r );





  return 0;
}
