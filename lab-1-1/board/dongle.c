/* Copyright (C) 2019 Atakan Colak  <ac16438@bristol.ac.uk>
 */

#include "dongle.h"

uint8_t hexchartoi(char hex) {
  if ('0' <= hex && hex <= '9') return hex - '0';
  if ('A' <= hex && hex <= 'F') return hex - 'A' + 10;
  if ('a' <= hex && hex <= 'f') return hex - 'a' + 10;
  else return -1;
}

int octetstr_rd( uint8_t* r, int n_r) {
  char size_A     = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
  char size_B     = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
  char semi_colon = scale_uart_rd(SCALE_UART_MODE_BLOCKING);

  int size = (hexchartoi(size_A) << 4) + hexchartoi(size_B);

  if (semi_colon != ':')  return -1;
  if (size + 3 > n_r)     return -1;

  for (int i = 0; i < size; ++i) {
    char hex_A     = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
    char hex_B     = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
    r[i] = (hexchartoi(hex_A) << 4) + hexchartoi(hex_B);
  }
  char eol = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
  if (!(eol == '\n' || eol == '\r')) return -1;
  return size;
}

void octetstr_wr( const uint8_t* x, int n_x ) {
  for (int i = n_x - 1; i >= 0; ++i)
    scale_uart_wr(SCALE_UART_MODE_BLOCKING, x[i]);
}

int main( int argc, char* argv[] ) {
  // initialise the development board, using the default configuration
  if( !scale_init( &SCALE_CONF ) ) {
    return -1;
  }

  int max_size = 256;
  int cur_size = 0;
  uint8_t * local_mem = malloc(sizeof(uint8_t) * max_size); 
  while( true ) {
      scale_delay_ms(1000);
      if (!scale_uart_rd_avail()) continue;
      cur_size = octetstr_rd(local_mem, max_size);
      if (!scale_uart_wr_avail()) continue;
      octetstr_wr(local_mem, cur_size);
  }
  return 0;
}



//   bool scale_uaint octetstr_rd( uint8_t* r, int n_r )rt_rd_avail()
// Check if UART is available for read (i.e., would doing so block or not).
// •
// bool scale_uart_wr_avail()
// Check if UART is available for write (i.e., would doing so block or not).
// •
// uint8_t scale_uart_rd( scale_uart_mode_t mode )
// Perform a blocking
// orint octetstr_rd( uint8_t* r, int n_r )
// non-blocking (per
// mode
// ) read of an 8-bit byte from the UART, returning said byte
// as the result.
// •
// void scale_uart_wr( scale_uart_mode_t mode, uint8_t x )
// Perform a blocking
// or
// non-blocking (per
// mode
// ) write of an 8-bit byte
// x
// to the UART

  // char x[] = "hello world";

  // while( true ) {
  //   // read  the GPI     pin, and hence switch : t   <- GPI
  //   bool t = scale_gpio_rd( SCALE_GPIO_PIN_GPI        );
  //   // write the GPO     pin, and hence LED    : GPO <- t
  //            scale_gpio_wr( SCALE_GPIO_PIN_GPO, t     );
  //
  //   // write the trigger pin, and hence LED    : TRG <- 1 (positive edge)
  //            scale_gpio_wr( SCALE_GPIO_PIN_TRG, true  );
  //   // delay for 500 ms = 1/2 s
  //   scale_delay_ms( 500 );
  //   // write the trigger pin, and hence LED    : TRG <- 0 (negative edge)
  //            scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );
  //   // delay for 500 ms = 1/2 s
  //   scale_delay_ms( 500 );
  //
  //   int n = strlen( x );
  //
  //   // write x = "hello world" to the UART
  //   for( int i = 0; i < n; i++ ) {
  //     scale_uart_wr( SCALE_UART_MODE_BLOCKING, x[ i ] );
  //   }
  // }
