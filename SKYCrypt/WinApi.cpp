#include "WinApi.h"
#include <process.h>

int WinExec(char *command,char *output) {
	return system(command);
}