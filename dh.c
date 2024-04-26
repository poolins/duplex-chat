#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/rand.h>

void print_openssl_error()
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0)
    {
        char *error_string = ERR_error_string(err, NULL);
        if (error_string)
        {
            printf("OpenSSL Error: %s\n", error_string);
            ERR_free_strings(); // Освобождаем память, выделенную ERR_error_string
        }
        else
        {
            printf("Failed to retrieve OpenSSL error string\n");
        }
    }
}

void dh_exchange_server(int client_socket, DES_cblock keys[3])
{
    // Инициализируем генератор псевдослучайных чисел
    if (RAND_poll() != 1)
    {
        handle_error("Error seeding PRNG");
    }

    // Создаем структуру для Диффи-Хеллмана
    DH *dh;
    dh = DH_new();
    if (!dh)
        handle_error("Error creating DH structure\n");
    else
    {
        printf("DH struct created\n");
    }

    // Генерируем параметры для Диффи-Хеллмана
    if (DH_generate_parameters_ex(dh, 1024, DH_GENERATOR_2, NULL) != 1)
    {
        DH_free(dh);
        printf("Error generating DH parameters\n");
        print_openssl_error();
    }
    else
    {
        printf("DH parameters succ generated\n");
        DHparams_print_fp(stdout, dh);
    }

    // Конвертируем параметры в буфер
    unsigned char *params_buf = NULL;
    int params_len = i2d_DHparams(dh, &params_buf);
    if (params_len <= 0)
    {
        handle_error("Error converting DH parameters to binary");
    }

    // Выполняем локальное вычисление пары публичный-приватный ключ
    if (!DH_generate_key(dh))
    {
        DH_free(dh);
        handle_error("Error generating DH key\n");
    }
    else
    {
        printf("DH key generated!\n");
    }

    // Конвертируем публичный ключ сервера в буфер
    unsigned char *pub_key_buf = NULL;
    pub_key_buf = BN_bn2hex(DH_get0_pub_key(dh));
    int pub_key_len = strlen(pub_key_buf);
    if (pub_key_len <= 0)
    {
        printf("Error converting DH public key to binary\n");
    }
    else
    {
        printf("DH public key converted to binary\n");
    }

    while (1)
    {
        // Отправляем клиенту буфер с парметрами Диффи-Хеллмана
        if (send(client_socket, params_buf, params_len, 0) == -1)
        {
            handle_error("Error sending DH parameters to client\n");
        }
        else
        {
            sleep(1);
            break;
        }
    }

    while (1)
    {
        // Отправляем публичный ключ сервера
        if (send(client_socket, pub_key_buf, pub_key_len, 0) == -1)
        {
            handle_error("Error sending server's public key to client\n");
        }
        else
        {
            printf("Server's public key sent\n");
            sleep(1);
            break;
        }
    }

    // Готовимся к получению публичного ключа клиента
    unsigned char *client_pub_key_buf = (unsigned char *)malloc(DH_size(dh));
    int client_pub_key_len;
    if (!client_pub_key_buf)
    {
        handle_error("Error allocating memory for client's public key\n");
    }

    while (1)
    {
        // Получаем публичный ключ клиента
        client_pub_key_len = recv(client_socket, client_pub_key_buf, 1024, 0);
        if (client_pub_key_len <= 0)
        {
            handle_error("Error receiving client's public key\n");
        }
        else
        {
            printf("Clien's public key recieved\n");
            sleep(1);
            break;
        }
    }

    // Преобразуем публичный ключ клиента в тип BIGNUM
    BIGNUM *client_pubkey_bignum = NULL;
    if (BN_hex2bn(&client_pubkey_bignum, client_pub_key_buf) == 0)
    {
        handle_error("Error converting client's public key from binary");
    }
    else
    {
        printf("Client's public key succesfully converted\n");
    }

    // Вычисляем общий секретный ключ
    unsigned char *shared_key = (unsigned char *)malloc(DH_size(dh));
    int shared_key_len = DH_compute_key(shared_key, client_pubkey_bignum, dh);
    if (shared_key_len <= 0)
    {
        handle_error("Error computing shared key");
    }
    else
    {
        printf("Shared key success!\n");
        for (int i = 0; i < 3; i++){
            strncpy((char *)keys[i], shared_key, 8);
        }
        printf("Shared Key: ");
        for (int i = 0; i < shared_key_len; ++i)
            printf("%02x", shared_key[i]);
    }
    printf("\n");
}

void dh_exchange_client(int client_socket, DES_cblock keys[3])
{
    DH *dh;
    unsigned char *params_buf = NULL;
    int params_len;

    // Готовимся к получению параметров Диффи-Хеллмана от сервера
    params_buf = (unsigned char *)malloc(1024);
    if (!params_buf)
    {
        handle_error("Error allocating memory");
    }

    while (1)
    {
        // Получаем параметры Диффи-Хеллмана от сервера
        params_len = recv(client_socket, params_buf, 1024, 0);
        if (params_len <= 0)
            handle_error("Error receiving DH parameters from server");
        else
        {
            printf("DH params received\n");
            sleep(1);
            break;
        }
    }

    // Преобразуем параметры в структуру DH
    dh = d2i_DHparams(NULL, (const unsigned char **)&params_buf, params_len);
    if (!dh)
        handle_error("Error converting DH parameters from binary\n");
    else
    {
        printf("DH parameters successfully converted\n");
        DHparams_print_fp(stdout, dh);
    }

    // Выполняем вычисление пары публичный-приватный ключ
    if (DH_generate_key(dh) != 1)
        handle_error("Error generating DH key\n");

    // Готовимся к получению публичного ключа сервера
    unsigned char *server_pub_key_buf = (unsigned char *)malloc(DH_size(dh));
    int server_pub_key_len;
    if (!server_pub_key_buf)
    {
        printf("Error allocating memory for client's public key\n");
    }

    while (1)
    {
        // Принимаем публичный ключ сервера
        server_pub_key_len = recv(client_socket, server_pub_key_buf, 1024, 0);
        if (server_pub_key_len <= 0)
        {
            handle_error("Error receiving server's public key\n");
        }
        else
        {
            printf("Server's public key received!\n");
            sleep(1);
            break;
        }
    }

    // Преобразуем публичный ключ сервера в BIGNUM
    BIGNUM *server_pubkey_bignum = NULL;
    if (BN_hex2bn(&server_pubkey_bignum, server_pub_key_buf) == 0)
    {
        handle_error("Error converting server's public key from binary\n");
    }
    else
    {
        printf("Server's public key successfully converted\n");
    }

    // Конвертируем публичный ключ клиента в бинарный буфер
    unsigned char *client_pub_key_buf = NULL;
    client_pub_key_buf = BN_bn2hex(DH_get0_pub_key(dh));
    int client_pub_key_len = strlen(client_pub_key_buf);
    if (client_pub_key_len <= 0)
    {
        handle_error("Error converting client's public key to binary\n");
    }

    // Отправляем публичный ключ клиента
    while (1)
    {
        if (send(client_socket, client_pub_key_buf, client_pub_key_len, 0) == -1)
            handle_error("Error sending client's public key to server\n");
        else
        {
            printf("Client sent public key to server!\n");
            sleep(1);
            break;
        }
    }

    // Вычисляем общий секретный ключ
    unsigned char *shared_key = (unsigned char *)malloc(DH_size(dh));
    int shared_key_len = DH_compute_key(shared_key, server_pubkey_bignum, dh);
    if (shared_key_len <= 0)
        printf("Error computing shared key\n");
    else
    {
        printf("Shared key success!\n");
        for (int i = 0; i < 3; i++){
            strncpy((char *)keys[i], shared_key, 8);
        }
        printf("Shared Key: ");
        for (int i = 0; i < shared_key_len; ++i)
            printf("%02x", shared_key[i]);
    }
    printf("\n");
}