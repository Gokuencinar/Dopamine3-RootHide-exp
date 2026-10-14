#include <stdio.h>

int main(int argc, char* argv[])
{
	// The historical RootHide 2 donor included an unimplemented executable
	// that returned success. Our actual hidden-root transaction lives in
	// DOBootstrapper; never report a fictitious successful install here.
	fputs("RootHide 3 standalone bootstrapper is not implemented; no changes made.\n", stderr);
	return 78;
}
