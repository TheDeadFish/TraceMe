#include "traceMe.cpp"

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
