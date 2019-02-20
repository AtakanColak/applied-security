/* Copyright (C) 2019 Atakan Colak  <ac16438@bristol.ac.uk>
 */

#include "dongle.h"

#define READ_BYTE           (scale_uart_rd(SCALE_UART_MODE_BLOCKING))
#define WRITE_BYTE(c)  (scale_uart_wr(SCALE_UART_MODE_BLOCKING, c))

uint8_t read_hex() {
  char hex = READ_BYTE;
  if ('A' <= hex && hex <= 'F') return hex - 'A' + 10;
  else return hex - '0';
}

uint8_t read_hex_byte() {
  uint8_t A     = read_hex();
  uint8_t B     = read_hex();
  return (A << 4) | B;
}

uint8_t itoh(uint8_t c) {
  c &= 0x0F;
  if (c < 10) return c + '0';
  else        return c + 'A'- 10;
}

void write_byte(uint8_t byte) {
  char A = itoh(byte >> 4);
  char B = itoh(byte);
  WRITE_BYTE(A);
  WRITE_BYTE(B);
}

int octetstr_rd( uint8_t* r, int n_r) {
  uint8_t size = read_hex_byte();
  char semi_colon = READ_BYTE;

  if (semi_colon != ':')  return -1;
  if (size > n_r )        return -1;

  for (int i = 0; i < size; ++i)
    r[i] = read_hex_byte();

  char eol = READ_BYTE;
  //if (!(eol == '\n' || eol == '\r')) return -1;
  return size;
}

void octetstr_wr( const uint8_t* x, int n_x ) {
  write_byte(n_x);
  WRITE_BYTE(':');

  for (int i = 0; i < n_x; ++i)
    write_byte(x[i]);

  WRITE_BYTE('\n');
  WRITE_BYTE('\r');
}

int main( int argc, char* argv[] ) {
  if( !scale_init( &SCALE_CONF ) ) return -1;

  int max_size = 256;
  uint8_t local_mem[max_size];
  while( true ) {
      scale_delay_ms(1000);
      scale_gpio_wr( SCALE_GPIO_PIN_TRG, true );
      int cur_size = octetstr_rd(local_mem, max_size);
      if (cur_size == -1) continue;
      octetstr_wr(local_mem, cur_size);
      scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );
      //break;
  }
  return 0;
}
