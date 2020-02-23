#include <stdshit.h>
#include <conio.h>
#include <traceMe.h>


const char progName[] = "TraceMe test";

double poop=200;

void fred()
{
	_cprintf("hello\n", poop+10);
}


int main()
{
	TraceMe::Begin(&fred);
	fred();
}
