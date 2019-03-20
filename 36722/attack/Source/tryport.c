#include <libserialport.h>
#include <stdio.h>
#include <stdlib.h>

const char* desired_port = "/dev/scale-board";
struct sp_port *port;

typedef int sp_return;

void CheckError(sp_return error, const char * message) {
  if(error != SP_OK) {
    fprintf(stdout, message);
    exit(EXIT_SUCCESS);
  }
}

int main(int argc, char *argv[]) {
  fprintf(stdout, "Opening port '%s' \n", desired_port);
  sp_return error = sp_get_port_by_name(desired_port,&port);
  CheckError(error, "Error at {sp_get_port_by_name}\n");
  error = sp_open(port, SP_MODE_WRITE);
  CheckError(error, "Error at {sp_open with SP_MODE_WRITE}\n");
  error = sp_set_baudrate(port,57600);
  CheckError(error, "Error at {sp_set_baudrate}\n");
  char test[6] = "01:00\x0D";
  int returned = sp_blocking_write(port, test[0], 6, 1000);
  fprintf(stdout, "%d bytes are written...\n", returned);
  // CheckError(error, "Error at {sp_blocking_write}\n");
  error = sp_close(port);
  CheckError(error, "Error at {sp_close}\n");
  // error = sp_open(port, SP_MODE_READ);
  // sp_set_baudrate(port,57600);
  // char response[7];
  // sp_nonblocking_read(port, response[0], 7);
  // fprintf(stdout, "%s\n", response);
  // if (error != SP_OK) return 0;
  // fprintf(stdout, "Successfully opened '%s' \n", desired_port);
  return 0;
}
