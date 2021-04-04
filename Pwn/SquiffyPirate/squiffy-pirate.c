#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void open_chest()
{
    puts("Yarr, the loot was found!!");
    system("cat flag.txt");
}

void pirate_dialogue()
{
    char buffer[20];
    puts("Ahoy, Matey! I can´t figure out how t' open the chest. Can ye help me 'n I will share the booty wit' ye!");
    puts("Help the pirate? [yes/no]");
    printf("> ");
    gets(buffer);

    if (strcmp(buffer, "yes") == 0)
    {
        puts("Thank ye, Matey.\n");
    }
    else
    {
        puts("Cor Blimey!\n");
    }
}

int main(int argc, char *argv[])
{
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    pirate_dialogue();
    return EXIT_SUCCESS;
}
