This challenge tries to simulate a simple vulnearbility where an attacker can modify one pointer 

We use our controll to modify the first next pointer in the linked list so that it points onto the first elements next pointer this will also corespond to the seconds elements value which we can modify when we want using this with the fact that we can leak the binary offset of the first element by printing the previous pointer of the second element, this of course before modifying the first elements next pointer. 

We can easily leak one pice of arbitrary data by changing the second elements value, which corisponds to the first elements next pointer  

We then change second->value to got.printf, we use this to leak out the adress of printf in libc then we simply change the printf got to point to our onegadget

We can from this quite simply trigger our one_gadget by executing the 2 command of the application