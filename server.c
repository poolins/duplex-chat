#include "inc.c"
#include "crypto.c"
#include "unsafe.c"
#include "dh.c"

#define SERVER_PORT 8080
#define SA struct sockaddr

int MODE;

int main(int argc, char *argv[])
{

	if (argc != 2)
	{
		printf("Usage: -u to unsafe connection, -s to des3, -dh to Diffie-Hellman alg.\n");
		return 1;
	}

	if (!strcmp(argv[1], "-u"))
	{
		// unsafe
		MODE = -1;
	}
	else if (!strcmp(argv[1], "-s"))
	{
		// des3
		MODE = 0;
	}
	else if (!strcmp(argv[1], "-dh"))
	{
		// Diffie-Hellman
		MODE = 1;
	}
	else
	{
		handle_error("Invalid command-line argument");
	}

	int sockfd, connfd, len;
	struct sockaddr_in servaddr, cli;

	// создание серверного сокета
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		handle_error("socket failed\n");
	}

	// Инициализация параметров сервера
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(SERVER_PORT);

	// Привязка сокета к адресу и порту
	if ((bind(sockfd, (SA *)&servaddr, sizeof(servaddr))) != 0)
	{
		handle_error("socket bind failed\n");
	}

	// Получение информации о порте и адресе сервера
	char ip_addr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(servaddr.sin_addr), ip_addr, INET_ADDRSTRLEN);
	printf("Server is listening on %s:%d\n", ip_addr, ntohs(servaddr.sin_port));

	// Ожидание подключения клиента
	if ((listen(sockfd, 5)) != 0)
	{
		handle_error("listen failed\n");
	}

	// Новое соединение
	len = sizeof(cli);
	connfd = accept(sockfd, (SA *)&cli, &len);
	if (connfd < 0)
	{
		handle_error("error with accepting another connection\n");
	}

	// Отправляем клиенту режим работы сервера
	// Конвертируем MODE в байтовый буфер
	char *mode_buffer = (unsigned char *)malloc(1024);
	memcpy(mode_buffer, &MODE, 1024);

	while (1)
	{
		if (send(connfd, mode_buffer, 1024, 0) == -1)
		{
			handle_error("Error sending server mode\n");
		}
		else
		{
			sleep(1);
			break;
		}
	}

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
		dh_exchange_server(connfd, des3_key);
		break;
	default:
		handle_error("Invalid parameter\n");
		break;
	}

	// Создание нового процесса
	int id = fork();
	if (id < 0)
	{
		handle_error("creating process finished with error");
	}

	if (id == 0)
	{
		// Код дочернего процесса - отправка сообщений
		if (MODE == -1)
		{
			write_unsafe_msg(connfd);
			exit(0);
		}
		else if (MODE == 0 || MODE == 1)
		{
			write_msg(connfd);
			exit(0);
		}
	}
	else
	{
		// Код родительского процесса - приём сообщений от клиента
		if (MODE == -1)
		{
			read_unsafe_msg(connfd, id);
			exit(0);
		}
		else if (MODE == 0 || MODE == 1)
		{
			read_msg(connfd, id);
			exit(0);
		}
	}
	// Закрытие сокетов
	close(connfd);
	close(sockfd);

	exit(0);
}
