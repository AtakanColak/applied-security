/* Copyright (C) 2019 Atakan Colak  <ac16438@bristol.ac.uk>
 */

#include "dongle.h"

uint8_t hexchartoi(char hex) {
  if ('0' <= hex && hex <= '9') return hex - '0';
  if ('A' <= hex && hex <= 'F') return hex - 'A' + 10;
  if ('a' <= hex && hex <= 'f') return hex - 'a' + 10;
  else return -1;
}

uint8_t read_byte() {
  char A     = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
  char B     = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
  return ((hexchartoi(A) << 4) & hexchartoi(B));
}

char itohexchar(uint8_t n, int i) {
  int s = n;
  if(i) s = (n >> 4);
  s &= 0x0F;
  if (s < 10) return s + '0';
  else        return s + 'A'- 10;
}

void write_byte(uint8_t byte) {
  char A = itohexchar(byte, 1);
  char B = itohexchar(byte, 0);
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, A);
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, B);
}

int octetstr_rd( uint8_t* r, int n_r) {
  int size = read_byte();
  char semi_colon = scale_uart_rd(SCALE_UART_MODE_BLOCKING);

  if (semi_colon != ':')  return -1;
  if (size > n_r )        return -1;

  for (int i = 0; i < size; ++i) 
    r[i] = read_byte();
  
  //char eol = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
  //if (!(eol == '\n' || eol == '\r')) return -1;
  return size;
}

void octetstr_wr( const uint8_t* x, int n_x ) {
  write_byte(n_x);
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, ':');

  for (int i = 0; i < n_x; ++i)
    write_byte(x[n_x - 1 - i]);

  scale_uart_wr(SCALE_UART_MODE_BLOCKING, '\r');
}

int main( int argc, char* argv[] ) {
  if( !scale_init( &SCALE_CONF ) ) return -1;

  int max_size = 256;
  int cur_size = 0;
  uint8_t local_mem[max_size];
  while( true ) {
      scale_delay_ms(1000);
      scale_gpio_wr( SCALE_GPIO_PIN_TRG, true  );
      cur_size = octetstr_rd(local_mem, max_size);
      if (cur_size == -1) {
        scale_gpio_wr( SCALE_GPIO_PIN_GPO, true );
        break;
      }
      octetstr_wr(local_mem, cur_size);
      scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );
      break;
  }
  return 0;
}

