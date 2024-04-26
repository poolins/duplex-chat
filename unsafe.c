void write_unsafe_msg(int sockfd)
{
    while (1)
    {
        printf("\n$ ");
        char message[256];
        fgets(message, sizeof(message), stdin);

        // Отправка сообщения
        if (send(sockfd, message, strlen(message), 0) < 0)
        {
            perror("error via sending message");
            return 2;
        }

        if (strncmp(stop_word, message, strlen(stop_word)) == 0)
        {
            printf("Disconnected.\n");
            close(sockfd);
            exit(0);
        }
    }
}

void read_unsafe_msg(int sockfd, int writePID)
{
    char correct = 1;
    while (1)
    {
        char recv_message[256];
        memset(recv_message, 0, sizeof(recv_message));

        if (!is_alive(writePID))
        {
            break;
        }

        // Приём сообщения от сервера
        if (recv(sockfd, recv_message, sizeof(recv_message), 0) < 0)
        {
            perror("error receive message");
            return 2;
        }

        if (recv_message[MAX_DATA_SIZE - 1] != 0 && recv_message[0] != 0)
        {
            correct = 0;
        }

        if (correct)
        {
            // Проверка на завершающее слово
            if (strncmp(stop_word, recv_message, strlen(stop_word)) == 0)
            {
                printf("Disconnected.\n");
                close(sockfd);
                kill(writePID, SIGKILL);
                break;
            }
        }

        printf("\n$Server: %s", recv_message);
    }
}
