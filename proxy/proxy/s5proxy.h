#pragma once
#include <winsock.h>
#include <stdint.h>
#include <string>
#include <mutex>
#include <condition_variable>


/* Command constants */
#define CMD_CONNECT         1
#define CMD_BIND            2
#define CMD_UDP_ASSOCIATIVE 3

/* Address type constants */
#define ATYP_IPV4   1
#define ATYP_DNAME  3
#define ATYP_IPV6   4

/* Connection methods */
#define METHOD_NOAUTH       0
#define METHOD_AUTH         2
#define METHOD_NOTAVAILABLE 0xff

/* Responses */
#define RESP_SUCCEDED       0
#define RESP_GEN_ERROR      1

/*heartbeat*/
#define METHOD_USER         0x80
//#define REPORT_HOST "162.211.181.174"
#define REPORT_HOST "114.246.68.140"
#define REPORT_PORT 6666

#pragma pack(push,1)
/* heartbeat */
struct HeartBeat {
	uint8_t version; /*05*/
	uint8_t method; /*80*/
	HeartBeat() :version(5), method(0x80){}
};

/* Handshake */
struct MethodIdentificationPacket {
	uint8_t version;
	uint8_t nmethods;
	/* uint8_t methods[nmethods]; */
};

struct MethodSelectionPacket {
	uint8_t version;
	uint8_t method;
	MethodSelectionPacket(uint8_t met) : version(5), method(met) {}
};


/* Requests */

struct SOCKS5RequestHeader {
	uint8_t version;
	uint8_t cmd;
	uint8_t rsv; /* = 0x00 */
	uint8_t atyp;
};

struct SOCK5IP4RequestBody {
	uint32_t ip_dst;
	uint16_t port;
};

struct SOCK5DNameRequestBody {
	uint8_t length;
	/* uint8_t dname[length]; */
};


/* Responses */

struct SOCKS5Response {
	uint8_t version;
	uint8_t cmd;
	uint8_t rsv;  /* = 0x00 */
	uint8_t atyp;
	uint32_t ip_src;
	uint16_t port_src;

	SOCKS5Response(bool succeded = true) : version(5), cmd(succeded ? RESP_SUCCEDED : RESP_GEN_ERROR), rsv(0), atyp(ATYP_IPV4) { }
};
#pragma pack(pop)


class s5proxy
{
public:
	s5proxy(int port, const std::string& username, const std::string& password, int maxs_client_count = 10);
	~s5proxy();
	bool exec();
	bool exec_report();
	bool test_connect();
	int connecttoreport();

private:
	int create_listenr();
	int recv_sock(int sock, char *buffer, uint32_t size);
	int peek_sock(int sock, char *buffer, uint32_t size);
	int send_sock(int sock, const char *buffer, uint32_t size);
	std::string int_to_str(uint32_t ip);
	int connect_to_host(uint32_t ip, uint16_t port);
	int read_variable_string(int sock, uint8_t *buffer, uint8_t max_sz);
	bool check_auth(int sock);
	bool handle_handshake(int sock, char *buffer);
	void set_fds(int sock1, int sock2, fd_set *fds);
	void do_proxy(int client, int conn, char *buffer);
	bool handle_request(int sock, char *buffer);
	void handle_connection(int sock);
	bool do_heartbeat(int socket);
	bool is_connect_OK(int rp_fd, int proxy_fd);

private:
	const static int BUF_SIZE = 256;
	int m_port;
	std::string m_username;
	std::string m_password;
	int client_count;
	int maxs_clients;
	int fd_server;

	std::mutex mtx_getHostName; 
	std::mutex mtx_count;
	std::condition_variable condition;
};

