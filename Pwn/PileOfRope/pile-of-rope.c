#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void haul(int a, int b)
{
    if ((a == 0xDEADBEEF) && (a ^ b == 0x8C9DEEAA) )
    {
        system("cat flag.txt");
    }
}

void pile_of_rope()
{
    char buffer[64];
    puts("Help the pirate hauling the ropes!");
    printf("> ");
    fgets(buffer, 128, stdin);
    printf("Yarr, thx..\n");
}

int main(int argc, char *argv[])
{
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    pile_of_rope();
    return EXIT_SUCCESS;
}
