#include "s5proxy.h"
#include <iostream>
#include <sstream>
#include <string.h>
#include <thread>
#include <time.h>


s5proxy::s5proxy(int port, const std::string& username, const std::string& password, int maxs_client_count)
:m_port(port), m_username(username), m_password(password), client_count(0), maxs_clients(maxs_client_count), fd_server(0), mtx_getHostName(), mtx_count(), condition()
{

}


s5proxy::~s5proxy()
{
	closesocket(fd_server);
}

bool s5proxy::exec()
{
	struct sockaddr_in echoclient;
	fd_server = create_listenr();
	if (fd_server == -1) {
		std::cout << "[-] Failed to create server\n";
		return false;
	}

	while (true) {

		int clientlen = sizeof(echoclient);
		int clientsock;

		{
			std::unique_lock<std::mutex> lock(mtx_count);
			if (client_count == maxs_clients)
				condition.wait(lock);
		}

		if ((clientsock = ::accept(fd_server, (struct sockaddr *) &echoclient, &clientlen)) > 0) {
			struct in_addr in;
			in.s_addr = echoclient.sin_addr.s_addr;
			std::cout << (char *)inet_ntoa(in) << "  : " << ntohs(echoclient.sin_port) << std::endl;

			{
				std::unique_lock<std::mutex> lock(mtx_count);
				client_count++;
			}
			std::thread t(&s5proxy::handle_connection, this, clientsock);
			t.detach();		
		}
	}

}

int s5proxy::connecttoreport()
{
	int res;
	while(true)
	{
#if 0
		res = connect_to_host(inet_addr("172.30.30.200"), 80);
		if(res == -1)
		{
			std::cout << "connect to zjs error." << std::endl;
			Sleep(1000*60*5);
			continue;
		}
		closesocket(res);
#endif
		res = connect_to_host(inet_addr(REPORT_HOST), REPORT_PORT);
		if(res == -1)
		{
			std::cout << "connect to report server error." << std::endl;
			Sleep(1000*60*50);
			continue;
		}else{
			break;
		}
	}
	return res;
}

bool s5proxy::exec_report()
{
	int rp_fd = connecttoreport(); //connect_to_host(inet_addr(REPORT_HOST), REPORT_PORT);
	struct timeval timeout; //select超时
	timeout.tv_sec = 60;
	timeout.tv_usec = 0;

	while (true)
	{
		fd_set readfds;
		int nfds = rp_fd + 1;
		FD_ZERO(&readfds);
		FD_SET(rp_fd, &readfds);
		int result = select(nfds, &readfds, 0, 0, &timeout);
		switch (result)
		{
		case 0:
			if (!do_heartbeat(rp_fd))
			{
				closesocket(rp_fd);
				std::cout << "[-] do_heartbeat error. try reconnect to report server\n";
				rp_fd = connecttoreport();

			}
			else{
				std::cout << "[-] do_heartbeat success.\n";
			}
			break;
		case SOCKET_ERROR:
			std::cout << "[-] Failed connect to report server\n";
			closesocket(rp_fd);
			rp_fd = connecttoreport();
			break;
		default:
			std::cout << "[-] a client come in \n";
			{	
				   std::unique_lock<std::mutex> lock(mtx_count);
				   if (client_count == maxs_clients)
					   condition.wait(lock);
					client_count++;
			}
			std::thread t(&s5proxy::handle_connection, this, rp_fd);
			t.detach();
			rp_fd = connect_to_host(inet_addr(REPORT_HOST), REPORT_PORT);
			break;
		} //end switch	
	} //end while(true)
	return false;
}

bool s5proxy::is_connect_OK(int rp_fd, int proxy_fd)
{
	int port = m_port;
	if (send_sock(rp_fd, (char *)&port, sizeof(int)) != sizeof(int))
	{
		std::cout << "[-] Failed send_sock to report server\n";
		return false;
	}

	struct timeval timeout; //select超时
	timeout.tv_sec = 60;
	timeout.tv_usec = 0;
	fd_set readfds;
	int nfds = max(proxy_fd, rp_fd) + 1;
	FD_ZERO(&readfds);
	set_fds(proxy_fd, rp_fd, &readfds);
	int result = select(nfds, &readfds, 0, 0, &timeout);
	if (result <= 0)
	{
		return false;
	}
	if (FD_ISSET(rp_fd, &readfds))
	{
		return false;
	}
	if (FD_ISSET(proxy_fd, &readfds))
	{
		int clientsock = ::accept(proxy_fd, NULL, NULL);
		if (clientsock <= 0)
		{
			return false;
		}
		char buf[3];
		if (recv_sock(clientsock, (char *)&buf, 2) != 2)
		{
			closesocket(clientsock);
			return false;
		}
		buf[2] = 0;
		if (strncmp(buf, "OK", 2) == 0)
		{
			closesocket(clientsock);
			return true;
		}
		closesocket(clientsock);
	}
	return false;
}

bool s5proxy::test_connect()
{
	int rp_fd = connect_to_host(inet_addr("118.244.213.128"), 4444);
	if (rp_fd == -1)
	{
		std::cout << "[-] Failed connect to report server\n";
		return false;
	}
	int proxy_fd = create_listenr();
	if (proxy_fd == -1) {
		std::cout << "[-] Failed to create server\n";
		closesocket(rp_fd);
		return false;
	}

	bool res = is_connect_OK(rp_fd, proxy_fd);
	closesocket(proxy_fd);
	closesocket(rp_fd);
	return res;
}

int s5proxy::create_listenr()
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
	echoserver.sin_port = htons(m_port);       /* server port */
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

int s5proxy::peek_sock(int sock, char *buffer, uint32_t size)
{
	int index = 0, ret;
	while (size) {
		if ((ret = ::recv(sock, &buffer[index], size, MSG_PEEK)) <= 0)
			return (!ret) ? index : -1;
		index += ret;
		size -= ret;
	}
	return index;
}

int s5proxy::recv_sock(int sock, char *buffer, uint32_t size)
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

int s5proxy::send_sock(int sock, const char *buffer, uint32_t size)
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


std::string s5proxy::int_to_str(uint32_t ip)
{
	std::ostringstream oss;
	for (unsigned i = 0; i < 4; i++) {
		oss << ((ip >> (i * 8)) & 0xFF);
		if (i != 3)
			oss << '.';
	}
	return oss.str();
}


int s5proxy::connect_to_host(uint32_t ip, uint16_t port)
{

	struct sockaddr_in serv_addr;
	struct hostent *server;
	int sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		return -1;
	memset((char *)&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	std::string ip_string = int_to_str(ip);
	{
		std::lock_guard<std::mutex> lock(mtx_getHostName);
		server = gethostbyname(ip_string.c_str());
		if (!server) {
			return -1;
		}
		memcpy((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
	}

	serv_addr.sin_port = htons(port);
	return !::connect(sockfd, (const sockaddr*)&serv_addr, sizeof(serv_addr)) ? sockfd : -1;
}

int s5proxy::read_variable_string(int sock, uint8_t *buffer, uint8_t max_sz)
{
	if (recv_sock(sock, (char*)buffer, 1) != 1 || buffer[0] > max_sz)
		return false;
	uint8_t sz = buffer[0];
	if (recv_sock(sock, (char*)buffer, sz) != sz)
		return -1;
	return sz;
}

bool s5proxy::check_auth(int sock)
{
	uint8_t buffer[128];
	if (recv_sock(sock, (char*)buffer, 1) != 1 || buffer[0] != 1)
		return false;
	int sz = read_variable_string(sock, buffer, 127);
	if (sz == -1)
		return false;
	buffer[sz] = 0;
	if (m_username != (char*)buffer)
		return false;
	sz = read_variable_string(sock, buffer, 127);
	if (sz == -1)
		return false;
	buffer[sz] = 0;
	if (m_password != (char*)buffer)
		return false;
	buffer[0] = 1;
	buffer[1] = 0;
	return send_sock(sock, (const char*)buffer, 2) == 2;
}

bool s5proxy::handle_handshake(int sock, char *buffer)
{
	MethodIdentificationPacket packet;
	int read_size = recv_sock(sock, (char*)&packet, sizeof(MethodIdentificationPacket));
	if (read_size != sizeof(MethodIdentificationPacket) || packet.version != 5)
	{
		std::cout << "acket.version != 5" << std::endl;
		return false;
	}
	if (recv_sock(sock, buffer, packet.nmethods) != packet.nmethods)
	{
		std::cout << "read nmethods error" << std::endl;
		return false;
	}
	MethodSelectionPacket response(METHOD_NOTAVAILABLE);
	for (unsigned i(0); i < packet.nmethods; ++i) {
#ifdef ALLOW_NO_AUTH
		if (buffer[i] == METHOD_NOAUTH)
			response.method = METHOD_NOAUTH;
#endif
		if (buffer[i] == METHOD_AUTH)
			response.method = METHOD_AUTH;
	}
	if (send_sock(sock, (const char*)&response, sizeof(MethodSelectionPacket)) != sizeof(MethodSelectionPacket) || response.method == METHOD_NOTAVAILABLE)
		return false;
	return (response.method == METHOD_AUTH) ? check_auth(sock) : true;
}

void s5proxy::set_fds(int sock1, int sock2, fd_set *fds) {
	FD_ZERO(fds);
	FD_SET(sock1, fds);
	FD_SET(sock2, fds);
}

void s5proxy::do_proxy(int client, int conn, char *buffer)
{
	fd_set readfds;
	int result, nfds = max(client, conn) + 1;
	set_fds(client, conn, &readfds);
	while ((result = select(nfds, &readfds, 0, 0, 0)) > 0) {
		if (FD_ISSET(client, &readfds)) {
			int recvd = recv(client, buffer, 256, 0);
			if (recvd <= 0)
				return;
			send_sock(conn, buffer, recvd);
		}
		if (FD_ISSET(conn, &readfds)) {
			int recvd = recv(conn, buffer, 256, 0);
			if (recvd <= 0)
				return;
			send_sock(client, buffer, recvd);
		}
		set_fds(client, conn, &readfds);
	}
}


bool s5proxy::handle_request(int sock, char *buffer)
{
	SOCKS5RequestHeader header;
	recv_sock(sock, (char*)&header, sizeof(SOCKS5RequestHeader));
	if (header.version != 5 || header.cmd != CMD_CONNECT || header.rsv != 0)
	{
		std::cout << "error: header.version " << header.version << " header.cmd " << header.cmd << " header.rsv " << header.rsv << std::endl;
		return false;
	}
	int client_sock = -1;
	switch (header.atyp) {
	case ATYP_IPV4:
	{
		 SOCK5IP4RequestBody req;
		 if (recv_sock(sock, (char*)&req, sizeof(SOCK5IP4RequestBody)) != sizeof(SOCK5IP4RequestBody))
		 {
			 std::cout << "recv SOCK5IP4RequestBody error." << std::endl;
			 return false;
		 }

		 std::cout << "connect to host." << std::endl;
		 client_sock = connect_to_host(req.ip_dst, ntohs(req.port));
		 break;
	}
	case ATYP_DNAME:
	{
		std::cout << "error: header.atyp is ATYP_DNAME" << std::endl;
		break;
	}
	default:
		std::cout << "error: header.atyp is" << header.atyp << std::endl;
		return false;
	}
	if (client_sock == -1)
		return false;
	SOCKS5Response response;
	response.ip_src = 0;
	response.port_src = m_port;
	send_sock(sock, (const char*)&response, sizeof(SOCKS5Response));
	do_proxy(client_sock, sock, buffer);
	shutdown(client_sock, 2);
	closesocket(client_sock);
	return true;
}


void s5proxy::handle_connection(int sock)
{
	char *buffer = new char[BUF_SIZE];
	if (handle_handshake(sock, buffer))
	{
		std::cout << "用户认证成功" << std::endl;
		handle_request(sock, buffer);
	}
	shutdown(sock, 2);
	closesocket(sock);
	delete[] buffer;

	std::unique_lock<std::mutex> lock(mtx_count);
	client_count--;
	if (client_count == maxs_clients - 1)
		condition.notify_one();
	return;
}

bool s5proxy::do_heartbeat(int socket)
{
	/*
	int res = connect_to_host(inet_addr("172.30.30.200"), 80);
	if(res == -1)
	{
		std::cout << "connect to zjs error." << std::endl;
		return false;
	}
	closesocket(res);
	*/

	HeartBeat heartbeat;
	if (send_sock(socket, (char *)&heartbeat, sizeof(HeartBeat)) != 2)
	{
		std::cout << "sent heart beat error!" << std::endl;
		return false;
	}
	int read_size = peek_sock(socket, (char*)&heartbeat, sizeof(HeartBeat));
	if (read_size != sizeof(HeartBeat))
	{
		std::cout << "socket reset" << std::endl;
		return false;
	}
	if (heartbeat.version == 5 && heartbeat.method == METHOD_USER)
	{
		recv_sock(socket, (char*)&heartbeat, sizeof(HeartBeat));
	}
	return true;
}