#include <iostream>
#include <winsock.h>
#include "s5proxy.h"
#include "WSock32init.h"
#include <upnpnat.h>


bool GetLocalIP(char* ip)
{
	int ret;
	//2.获取主机名
	char hostname[256];
	ret = gethostname(hostname, sizeof(hostname));
	if (ret == SOCKET_ERROR)
	{
		return false;
	}
	//3.获取主机ip
	HOSTENT* host = gethostbyname(hostname);
	if (host == NULL)
	{
		return false;
	}
	//4.转化为char*并拷贝返回
	//strcpy_s(ip,20, inet_ntoa(*(in_addr*)*host->h_addr_list));
	for (int i = 0; host->h_addr_list[i] != 0; ++i) {
		char *p =  inet_ntoa(*(in_addr*)host->h_addr_list[i]);
		if(strncmp("192", p, 3) == 0)
		{
			strcpy_s(ip,20, p);
		}
	}
	return true;
}

int upnp()
{
	char ip[20];
	if (!GetLocalIP(ip))
	{
		return -1;
	}
	UPNPNAT nat;
	nat.init(5, 10);
	if (!nat.discovery()){
		std::cout << "discovery error is " << nat.get_last_error() << std::endl;
		return -1;
	}
	if (!nat.add_port_mapping("test", ip, 5555, 5555, "TCP")){
		std::cout << "add_port_mapping error is " << nat.get_last_error() << std::endl;
		return -1;
	}
	std::cout << "add port mapping succ." << std::endl;
	return 0;
}




int main(int argc, char** argv)
{
	bool upnp_falg = false;
	WSock32init wsinit;

	s5proxy s5p(5555, "zjs", "zjs123");

	//local
	//s5p.exec();


	//report

	if (!s5p.exec_report())
	{
		std::cout << "start error!" << std::endl;
	}

	return 0;
}