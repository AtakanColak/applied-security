#include <libserialport.h>
#include <stdio.h>

const char* desired_port = "/dev/scale-board";
struct sp_port *port;

typedef int sp_return;

int main(int argc, char *argv[]) {
  // xlist_ports();
  fprintf(stdout, "Opening port '%s' \n", desired_port);
  sp_return error = sp_get_port_by_name(desired_port,&port);
  // if (error != SP_OK) return 0;
  error = sp_open(port, SP_MODE_WRITE);
  if (error != SP_OK)  {
    return 0;
  }
  sp_set_baudrate(port,57600);
  sp_nonblocking_write(port, "01:00\x0D", 6);
  sp_close(port);
  // error = sp_open(port, SP_MODE_READ);
  // sp_set_baudrate(port,57600);
  // char response[7];
  // sp_nonblocking_read(port, response[0], 7);
  // fprintf(stdout, "%s\n", response);
  // if (error != SP_OK) return 0;
  // fprintf(stdout, "Successfully opened '%s' \n", desired_port);
  return 0;
}
