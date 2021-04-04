To solve this challenge one have to look both at the packet capture and the .so 

From the packet capture by filtering for http.request we can see that there has been 3 requests 2 to favicon.ico 
and a post request to login.php
The post request with username hacker and password 	my_super_secure_password
Armed with this information we can take a look at the chal.so file 

We see that it is composed of a couple functions 2 of which are called rc4_setup and rc4_crypt, searching for these 2 functions we come over https://github.com/philanc/luazen/blob/master/src/rc4.c whicxh seems to correspond to the functions in the binary


Looking at the code in IDA we quickly find this 
```c 
	v28 = (read_post_struct *)readPost(v7);
       if ( !key )
        {
          if ( !v28 )
            goto LABEL_43;
          v29 = (const char *)v28->post_key;
          if ( !v28->post_key )
            goto LABEL_43;
          username_hacker = 0LL;
          password = 0LL;
          do
          {
            if ( !v28->post_value )
              break;
            if ( !strcmp(v29, "username") && !strcmp((const char *)v28->post_value, "hacker") ) // Is the key username and password hacker?
              username_hacker = apr_pstrdup(*(_QWORD *)v7, v28->post_value);
            if ( !strcmp((const char *)v28->post_key, "password") )// If the key is  password
              password = (const char *)apr_pstrdup(*(_QWORD *)v7, v28->post_value);
            v29 = (const char *)v28[1].post_key;
            ++v28;
          }
          while ( v29 );
          if ( password && username_hacker )
          {
            len_password = strlen(password);
            rc4_setup(ctx, (__int64)password, len_password);
            key = 1;
            ap_set_content_type(v7, "text/plain");
            v4 = byte_9 + 5;
            a1 = "Authenticated!";
            ap_rwrite("Authenticated!", 14LL, v7);
            v10 = 4294967294LL;
          }
          else
          {
LABEL_43:
            ap_set_content_type(v7, "text/plain");
            v4 = (char *)&word_12;
            a1 = "Not authenticated!";
            ap_rwrite("Not authenticated!", 18LL, v7);
            v10 = 0xFFFFFFFFLL;
          }
```
From this we can see that if an user send's a post request with the username hacker we will initialize rc4 with a key coresponding to the password sent in.
This will also set a KEY flag 

So now we know what password does we can start writing our solve script

```c
	
	rc4_ctx ctx;
	
	rc4_setup(&ctx,"my_super_secure_password",strlen("my_super_secure_password"));
```
are the first lines 

```c
     if ( (!v12 && !v13) == v12 && key )
      {
        secret_file_name = (char *)calloc(1uLL, 0x12uLL);
        rc4_crypt(ctx, (__int64)&unk_208A, (__int64)secret_file_name, 18);
        v4 = "r";
        a1 = secret_file_name;
        fp = fopen(secret_file_name, "r");
```
We can se that it opens a file after decrypting the string coresponding to this
```c
char *tmpName = "\x57\x5C\x79\xDB\xF2\x44\xB2\x18\x91\x5B\x0D\x8E\xD9\xCF\x56\x06\x53\x9E\x00\x72\x62\x00";
```
This string decrypted is the file that get's opened 

With this information our solve script becomes
```c
	rc4_ctx ctx;
	
	rc4_setup(&ctx,"my_super_secure_password",strlen("my_super_secure_password"));
    char *tmpName = "\x57\x5C\x79\xDB\xF2\x44\xB2\x18\x91\x5B\x0D\x8E\xD9\xCF\x56\x06\x53\x9E\x00\x72\x62\x00";
    char *filename = calloc(sizeof(char),0x12uLL);
    rc4_crypt(&ctx,tmpName,filename,0x12uLL);

    printf("tmpName %s\n",filename);
```
which outputs tmpName /srv/http/flag.txt

The content of the file get's encrypted again with the same context as the earlier string 



After this we can see that the program opens another file we can guess from earlier code  and from the fact that this is a ctf challenge that the file is favicon.ico.

```c
 secret_file_name = (char *)calloc(1uLL, 0x12uLL);
        rc4_crypt(ctx, (__int64)&unk_208A, (__int64)secret_file_name, 18);
        v4 = "r";
        a1 = secret_file_name;
        fp = fopen(secret_file_name, "r");
        if ( !fp )
          goto LABEL_21;
        fseek(fp, 0LL, 2);
        lenghtOf_flag = ftell(fp);
        fseek(fp, 0LL, 0);
        a1 = (_BYTE *)(&dword_0 + 1);
        v4 = (char *)(lenghtOf_flag + 1);
        flag_buffer = calloc(1uLL, lenghtOf_flag + 1);
        v19 = flag_buffer;
        if ( !flag_buffer )
          goto LABEL_21;
        fread(flag_buffer, 1uLL, lenghtOf_flag, fp);
        fclose(fp);
        v19[lenghtOf_flag + 1] = 0;
        encrypted_flag = (char *)calloc(1uLL, lenghtOf_flag + 1);
        rc4_crypt(ctx, (__int64)v19, (__int64)encrypted_flag, lenghtOf_flag);
        free(v19);
        output_file = fopen(*((const char **)v7 + 43), "rb");// filename acording to filename struct
        fseek(output_file, 0LL, 2);
        file_lenght = ftell(output_file);
        fclose(output_file);
        a1 = (_BYTE *)(&dword_0 + 1);
        v22 = apr_file_open(&v37, *((_QWORD *)v7 + 43), 1LL, 4095LL, *(_QWORD *)v7);
        v4 = (char *)(file_lenght + 4);
        file_buffer = (char *)calloc(1uLL, file_lenght + 4);
        if ( !file_buffer )
          goto LABEL_21;
        if ( v22 )
        {
          free(file_buffer);
          a1 = encrypted_flag;
          free(encrypted_flag);
          v10 = 0xFFFFFFFFLL;
        }
        else
        {
          a1 = v37;
          v4 = file_buffer;
          if ( (unsigned int)apr_file_read(v37, file_buffer, &file_lenght) )
          {
LABEL_21:
            v10 = 500LL;
            goto LABEL_22;
          }
          free(secret_file_name);
          if ( lenghtOf_flag )
          {
            v32 = file_buffer + 0x1E0;
            flag_curs = encrypted_flag;
            v34 = &encrypted_flag[lenghtOf_flag];
            do
            {
              v35 = *flag_curs++;
              *v32 ^= v35;
              v32 += 16;
            }
            while ( v34 != flag_curs );
          }
```

We can see that the favicon file gets read in and then it gets xored at specific offsets with the encrypted version of flag. 

```c
 if ( lenghtOf_flag )
          {
            v32 = file_buffer + 0x1E0;
            flag_curs = encrypted_flag;
            v34 = &encrypted_flag[lenghtOf_flag];
            do
            {
              v35 = *flag_curs++;
              *v32 ^= v35;
              v32 += 16;
            }
            while ( v34 != flag_curs );
          }
```

Because of this we can get the bytes that coresponds to the flag by just xoring the two favicon.ico files. I found a python script which would xor the two files using this with the algorithm I created the final solve script 
