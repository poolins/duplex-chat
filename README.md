### Compile
```
gcc server.c -o server -lssl -lcrypto
```
```
gcc client.c -o client -lssl -lcrypto
```
### Launch server
+ without encryption
```
./server -u 
```
+ triple-DES encryption with OpenSSL (keys from text file)
 ```
./server -s
```
+ generation triple-DES keys with Diffie-Hellman algorithm
 ```
./server -dh
```
### Launch client
 ```
./client 0.0.0.0 8080
```
После подключения, клиент будет работать в том же режиме шифрования, что и сервер. Задать режим шифрования при запуске клиента невозможно.
### Watch packets with tcpdump
```
sudo tcpdump -i lo -A
```
