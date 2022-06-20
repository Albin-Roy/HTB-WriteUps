# Jeeves, Binary Exploitation - HTB



We have jeeves.zip as the task file. Unzip it.

```
unzip jeeves.zip
```





We can enter a string and it prints out the entered string.

```
┌──(root💀kali)-[~/htb/challenges/jeeves]
└─# ./jeeves       
Hello, good sir!
May I have your name? Albin
Hello Albin, hope you have a good day!

```



Now lets's analyse the binary using ghidra

<img title="" src="file:///root/Pictures/Screenshot_2022-06-10_04_51_04.png" alt="">



Here,  char local_48 is an array with 44 elements. So, let's try to enter a string having more than 44 characters.

```
┌──(root💀kali)-[~/htb/challenges/jeeves]
└─# python -c "print('A' * 50)"                                               
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                                                                                                                                                                                             
┌──(root💀kali)-[~/htb/challenges/jeeves]
└─# ./jeeves
Hello, good sir!
May I have your name? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, hope you have a good day!

```



It doesn't work. So lets enter a string of 100 characters.

```
┌──(root💀kali)-[~/htb/challenges/jeeves]
└─# ./jeeves                    
Hello, good sir!
May I have your name? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, hope you have a good day!
zsh: segmentation fault  ./jeeves

```

Yes, memory has overflowed and a segmentation fault has arised.


