#include "inc.c"
#include "crypto.c"
#include "unsafe.c"
#include "dh.c"
#define SERVER_PORT 8080
#define SA struct sockaddr

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("Usage: %s <server_ip_address> <server_port>\n", argv[0]);
		return 1;
	}

	char *server_ip_address = argv[1];
	int server_port = atoi(argv[2]);

	int sockfd, connfd, i;
	struct sockaddr_in server_address, cli;
	int err = 0;
	// Создание сокета
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		handle_error("failed to create socket\n");
	}

	// Настройка параметров сервера
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = inet_addr(server_ip_address);
	server_address.sin_port = htons(server_port);

	// Подключение к серверу
	if (connect(sockfd, (SA *)&server_address, sizeof(server_address)) < 0)
	{
		handle_error("failed to connect to the server\n");
	}

	// Получение режима работы сервера
	int mode_len;
	int MODE;
	char *mode_buffer = NULL;
	mode_buffer = (unsigned char *)malloc(1024);
	while (1)
	{
		mode_len = recv(sockfd, mode_buffer, 1024, 0);
		if (mode_len <= 0)
		{
			handle_error("Error recieving mode from server\n");
		}
		else
		{
			sleep(1);
			break;
		}
	}

	memcpy(&MODE, mode_buffer, sizeof(int));

	switch (MODE)
	{
	case -1:
		printf("Using unsafe mode\n");
		break;
	case 0:
		printf("Using des3 keys from file\n");
		read_keys("keys", des3_key);
		break;
	case 1:
	    printf("Using Diffie-Hellman keys\n");
		dh_exchange_client(sockfd, des3_key);
		break;
	default:
		handle_error("Invalid parameter\n");
		break;
	}

	// Создание нового процесса
	int id = fork();
	if (id < 0)
	{
		handle_error("forking error\n");
	}

	if (id == 0)
	{
		// Код дочернего процесса - отправка сообщений серверу
		if (MODE == -1)
		{
			write_unsafe_msg(sockfd);
			exit(0);
		}
		else if (MODE == 0 || MODE == 1)
		{
			write_msg(sockfd);
			exit(0);
		}
	}
	else
	{
		// Код родительского процесса - приём сообщений от сервера
		if (MODE == -1)
		{
			read_unsafe_msg(sockfd, id);
			exit(0);
		}
		else if (MODE == 0 || MODE == 1)
		{
			read_msg(sockfd, id);
			exit(0);
		}
	}
	// Закрытие сокета
	close(sockfd);

	return 0;
}
