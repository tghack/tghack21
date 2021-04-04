#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void unlock_chest()
{
    char buffer[128];
    puts("The chest is locked...\n *thinking*");
    sleep(1);

    puts("You see a shovel in the corner, hidden behind some crates.");
    sleep(1);

    puts("Try to force the chest open with the shovel?");
    printf("> ");
    gets(buffer);
    printf(buffer);

    if (strcmp(buffer, "yes") == 0)
    {
        puts("\n\nArr. You broke the shovel attempting to break the lock..!\n");
    }
    else
    {
        puts("\n\nYou will have to try harder...\n");
        printf("> ");
        gets(buffer);
        printf(buffer);
        printf("\n");
    }
}

int main(int argc, char *argv[])
{
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    unlock_chest();
    return EXIT_SUCCESS;
}
