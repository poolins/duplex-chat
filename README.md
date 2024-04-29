Compile:
```
gcc server.c -o server -lssl -lcrypto
```
```
gcc client.c -o client -lssl -lcrypto
```
Launch parameters: 

-u   without encryption

-s   triple-DES encryption with OpenSSL (keys from text file)

-dh  generation triple-DES keys with Diffie-Hellman algorithm

Watch packets with tcpdump:
```
sudo tcpdump -i lo -A
```
