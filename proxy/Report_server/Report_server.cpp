// Report_server.cpp : Defines the entry point for the console application.
//

#include<iostream>
#include<vector>
#include <stdint.h>
#include <thread>

#ifdef WIN32
#include <winsock.h>
#include "../proxy/WSock32init.h"
#else
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif


#define BUFFERSIZE 512

using namespace std;


struct HeartBeat {
	uint8_t version; /*05*/
	uint8_t method; /*80*/
	HeartBeat() :version(5), method(0x80){}
};

#ifndef WIN32
int closesocket(int fd)
{
	return close(fd);
}
#endif

int create_listenr(short port)
{
	int serversock;
	struct sockaddr_in echoserver;
	/* Create the TCP socket */
	if ((serversock = ::socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		std::cout << "[-] Could not create socket.\n";
		return -1;
	}
	/* Construct the server sockaddr_in structure */
	memset(&echoserver, 0, sizeof(echoserver));       /* Clear struct */
	echoserver.sin_family = AF_INET;                  /* Internet/IP */
	echoserver.sin_addr.s_addr = htonl(INADDR_ANY);   /* Incoming addr */
	echoserver.sin_port = htons(port);       /* server port */
	/* Bind the server socket */
	if (::bind(serversock, (struct sockaddr *) &echoserver, sizeof(echoserver)) < 0) {
		std::cout << "[-] Bind error.\n";
		return -1;
	}
	/* Listen on the server socket */
	if (::listen(serversock, 200) < 0) {
		std::cout << "[-] Listen error.\n";
		return -1;
	}
	return serversock;
}

int recv_sock(int sock, char *buffer, uint32_t size)
{
	int index = 0, ret;
	while (size) {
		if ((ret = ::recv(sock, &buffer[index], size, 0)) <= 0)
			return (!ret) ? index : -1;
		index += ret;
		size -= ret;
	}
	return index;
}

int send_sock(int sock, const char *buffer, uint32_t size)
{
	int index = 0, ret;
	while (size) {
		if ((ret = ::send(sock, &buffer[index], size, 0)) <= 0)
			return (!ret) ? index : -1;
		index += ret;
		size -= ret;
	}
	return index;
}

void do_report(int clientFD, int serverFD)
{
	fd_set readfds;	
	char * buffer = (char *)malloc(sizeof(char)* BUFFERSIZE);
	int maxfdp = clientFD > serverFD ? clientFD + 1 : serverFD + 1;
	FD_ZERO(&readfds);
	FD_SET(clientFD, &readfds);
	FD_SET(serverFD, &readfds);
	while (select(maxfdp, &readfds, 0, 0, 0) > 0) {
		if (FD_ISSET(clientFD, &readfds)) {
			int recvd = recv(clientFD, buffer, 256, 0);
			if (recvd <= 0)
				break;
			send_sock(serverFD, buffer, recvd);
		}
		if (FD_ISSET(serverFD, &readfds)) {
			int recvd = recv(serverFD, buffer, 256, 0);
			if (recvd <= 0)
				break;
			send_sock(clientFD, buffer, recvd);
		}
		FD_ZERO(&readfds);
		FD_SET(clientFD, &readfds);
		FD_SET(serverFD, &readfds);
	}
	free(buffer);
	closesocket(clientFD);
	closesocket(serverFD);
}

int main(int argc, char* argv[])
{
#ifdef WIN32
	WSock32init wsinit;
#endif
	std::vector<int> SFD_vector;
	int serverFD = create_listenr(6666);
	int clientFD = create_listenr(5555);

	struct sockaddr_in echoclient;
	int clientlen = sizeof(echoclient);

	while (true)
	{
		fd_set acceptfds;
		int maxfdp = serverFD + 1;
		FD_ZERO(&acceptfds);
		FD_SET(serverFD, &acceptfds);
		maxfdp = clientFD>maxfdp ? clientFD + 1 : maxfdp; //描述符最大值加1 
		FD_SET(clientFD, &acceptfds);

		for (auto it = SFD_vector.begin(); it != SFD_vector.end(); ++it)
		{
			FD_SET(*it, &acceptfds);
			maxfdp = *it>maxfdp ? *it + 1 : maxfdp; //描述符最大值加1 
		}

		int result = select(maxfdp, &acceptfds, 0, 0, NULL);
		switch (result)
		{
		case 0:
			std::cout << "[-] why. is it time out? but timeout is NULL" << std::endl;
			break;
		case -1:
			std::cout << "[-] select errorno: " << errno << std::endl;;
			break;
		default:
			if (FD_ISSET(serverFD, &acceptfds) > 0)
			{
				int fd = 0;
				if ((fd = ::accept(serverFD, (struct sockaddr *) &echoclient, &clientlen)) > 0) {
					struct in_addr in;
					in.s_addr = echoclient.sin_addr.s_addr;
					std::cout <<"server: "<< (char *)inet_ntoa(in) << "  : " << ntohs(echoclient.sin_port) << std::endl;
					SFD_vector.push_back(fd);

				}
			}
			if (FD_ISSET(clientFD, &acceptfds) > 0)
			{
				int fd = 0;
				if ((fd = ::accept(clientFD, (struct sockaddr *) &echoclient, &clientlen)) > 0) {
					struct in_addr in;
					in.s_addr = echoclient.sin_addr.s_addr;
					std::cout << "client: " << (char *)inet_ntoa(in) << "  : " << ntohs(echoclient.sin_port) << std::endl;
					if (SFD_vector.empty())
					{
						closesocket(fd);
					}
					else{
						std::thread t(do_report, fd, SFD_vector.back());
						t.detach();
						SFD_vector.pop_back();
					}

				}
			}
			//HeartBeat
			for (auto it = SFD_vector.begin(); it != SFD_vector.end(); )
			{
				if (FD_ISSET(*it, &acceptfds) > 0)
				{
					HeartBeat heartbeat;
					if (recv_sock(*it, (char*)&heartbeat, sizeof(HeartBeat)) != sizeof(HeartBeat))
					{
						closesocket(*it);
						it = SFD_vector.erase(it);
						std::cout << "heartbeat error!" << std::endl;
						continue;
					}
					if (send_sock(*it, (char *)&heartbeat, sizeof(HeartBeat)) != sizeof(HeartBeat))
					{
						closesocket(*it);
						it = SFD_vector.erase(it);
						std::cout << "heartbeat error!" << std::endl;
						continue;
					}
					std::cout << "heartbeat"<< std::endl;				
				}
				++it;
			}
			break;
		} //end switch	
	} //end while(true)

	return 0;
}

