#define OPENSSL_API_COMPAT 0x10101000L
#include <openssl/des.h>

#define MAX_DATA_SIZE 80
DES_cblock des3_key[3];

void read_keys(const char *filename, DES_cblock keys[3])
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Failed to open keys file.\n");
        exit(1);
    }

    for (int i = 0; i < 3; ++i)
    {
        char key_str[MAX_DATA_SIZE];
        if (fgets(key_str, MAX_DATA_SIZE, file) == NULL)
        {
            printf("Failed to read key from file.\n");
            exit(1);
        }
        // Удаление символа новой строки, если есть
        char *newline = strchr(key_str, '\n');
        if (newline != NULL)
            *newline = '\0';
        // Копирование ключа в структуру DES_cblock
        strncpy((char *)keys[i], key_str, 8);
    }

    fclose(file);
}

void cryptographic(const unsigned char *str, unsigned char *enc_str, int encrypt)
{
    DES_key_schedule schedule1, schedule2, schedule3;
    DES_set_key_unchecked(&des3_key[0], &schedule1);
    DES_set_key_unchecked(&des3_key[1], &schedule2);
    DES_set_key_unchecked(&des3_key[2], &schedule3);

    for (int i = 0; i < MAX_DATA_SIZE / 8; i++)
    {
        const char *current_block = str + i * 8;
        char *next_block = enc_str + i * 8;
        DES_ecb3_encrypt((const_DES_cblock *)current_block, (DES_cblock *)next_block, &schedule1, &schedule2, &schedule3, encrypt);
    }
}

// Функция для чтения и дешифрования сообщения
void read_msg(int sockfd, int writePID)
{
    // Буфер для первичный данных
    char buffer[MAX_DATA_SIZE];
    // Буфер для зашифрованных/дешифрованных данных
    char buffer_crypto[MAX_DATA_SIZE];
    // Указатель на рабочий буфер
    char *working_buffer = buffer;
    while (1)
    {
        // Обнуления буфера
        bzero(buffer, MAX_DATA_SIZE);

        // Чтение сообщения от сервера
        read(sockfd, buffer, sizeof(buffer));

        if (!is_alive(writePID))
        {
            break;
        }

        // Обнуление буфера для дешифрованного сообщения
        bzero(buffer_crypto, MAX_DATA_SIZE);

        // Дешифрование принятого сообщения
        cryptographic(buffer, buffer_crypto, DES_DECRYPT);
        char correct = 1;

        // Проверка корректности сообщения
        // Проверка не является ли сообщение пустым или содержит только нулевые символы
        if (working_buffer[MAX_DATA_SIZE - 1] != 0 && working_buffer[0] != 0)
        {
            correct = 0;
            bzero(buffer_crypto, MAX_DATA_SIZE);
            cryptographic(buffer, buffer_crypto, DES_DECRYPT);
            if (buffer_crypto[MAX_DATA_SIZE - 1] == 0)
            {
                // Если последний символ равен 0, то дешифрованное сообщение корректно
                working_buffer = buffer_crypto;
                correct = 1;
            }
        }
        if (correct)
        {
            // Проверка на завершающее слово
            if (strncmp(stop_word, working_buffer, strlen(stop_word)) == 0)
            {
                printf("Disconnected.\n");
                close(sockfd);
                kill(writePID, SIGKILL);
                break;
            }
            // Вывод дешифрованного сообщения
            if (working_buffer[0] != 0)
            {
                printf("\nRecieved message: %s", working_buffer);
            }
        }
    }
}

// Функция для отправки и шифрования сообщения
void write_msg(int sockfd)
{
    char buffer[MAX_DATA_SIZE];
    char buffer_crypto[MAX_DATA_SIZE];
    char *working_buffer = buffer;
    int i = 0;
    // Настройка рабочего буфера для шифрования
    working_buffer = buffer_crypto;
    // Приглашение для ввода сообщения
    while (1)
    {
        printf("\n$ ");
        // Обнуление буфера
        bzero(buffer, MAX_DATA_SIZE);
        i = 0;
        // Считывания символов сообщения с клавиатуры
        while ((buffer[i++] = getchar()) != '\n')
            if (i == MAX_DATA_SIZE - 2)
            {
                buffer[i] = '\n';
                buffer[i + 1] = '\0';
                break;
            }
        // Обнуление буфера для шифрованного сообщения
        bzero(buffer_crypto, MAX_DATA_SIZE);
        // Шифрование для введённого сообщения
        cryptographic(buffer, buffer_crypto, DES_ENCRYPT);
        // Отправка шифрованного сообщения серверу
        write(sockfd, working_buffer, sizeof(buffer));
        // Проверка на завершающее слово
        if (strncmp(stop_word, buffer, strlen(stop_word)) == 0)
        {
            printf("Disconnected.\n");
            close(sockfd);
            exit(0);
        }
    }
}
