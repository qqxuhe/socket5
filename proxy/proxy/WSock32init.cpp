#include "WSock32init.h"
#include <iostream>
#include <winsock.h>

#pragma comment(lib,"WSock32.Lib")
WSock32init::WSock32init()
{
	WSADATA wsaData;
	int Ret;
	if ((Ret = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
	{
		std::cout << "WSAStartup failed with error " << Ret << std::endl;
	}
}


WSock32init::~WSock32init()
{
	WSACleanup();
}
