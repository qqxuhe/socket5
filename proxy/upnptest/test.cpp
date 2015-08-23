#include <iostream>
#include <upnpnat.h>

#pragma comment(lib,"WSock32.Lib")

int main(int argc, char** argv)
{	
	UPNPNAT nat;
	nat.init(5,10);
	if(!nat.discovery()){
		std::cout << "discovery error is " << nat.get_last_error() << std::endl;
		return -1;
	}
	if(!nat.add_port_mapping("test","192.168.1.102",5555,5555,"TCP")){
		std::cout << "add_port_mapping error is " << nat.get_last_error() << std::endl;
		return -1;
	}
}