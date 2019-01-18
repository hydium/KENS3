/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <utility>
#include <E/Networking/E_RoutingInfo.hpp>

namespace E
{

struct write_mapping 
{
	uint16_t buf_index; // at what point the segment start in the buffer 
	uint16_t size; // size of the segment
	uint32_t seq_num;
	bool sent;
};

struct socket_params 
{
	std::map<uint16_t, read_mapping> read_map;
	std::map<uint32_t, write_mapping> write_map;
	UUID syscallUUID;
	UUID timer;
	uint32_t src_addr;
	uint32_t dest_addr;
	char *payload;
	struct listening_params *listen_struct;
	uint32_t seq_num; // last seq num of socket (sent from the socket)
	uint32_t smallest_valid_seq_num;
	uint32_t ack_num; // last ack sent FROM the socket
	uint32_t last_ack_received; // last ack sent TO the socket
	uint16_t last_byte_read;
	uint16_t read_window;
	char *read_buf;
	uint16_t write_window;
	char *write_buf;
	uint16_t peer_window;
	uint32_t count;
	char *given_buf;
	uint16_t src_port;
	uint16_t dest_port;
	uint8_t state;
	uint8_t mode;
	uint8_t duplicate_count;
	bool bound;
	bool passive;
	bool closing;
	bool fast_retransmitted;
	bool connecting;
	bool timer_set;
};

struct listening_params
{
	uint32_t backlog;
	uint32_t pending_count;
	struct pending_connection *pending_list;
	uint32_t waiting_count;
	struct waiting_connection *waiting_list;
	UUID syscallUUID; // fields of a blocked accept
	struct sockaddr_in* addr; 
	socklen_t *len;
	int pid;
};

struct waiting_connection
{
	uint32_t seq_num;
	uint32_t dest_addr;
	uint32_t src_addr;
	uint32_t ack_num;
	uint32_t last_ack_received;
	uint16_t dest_port;
	uint16_t peer_window;
	uint8_t state;
};

struct pending_connection
{
	UUID timer;
	uint16_t dest_port;
	uint32_t ack_num;
	uint32_t dest_addr;
	uint32_t src_addr;
};


//states of read_mapping
// uint8_t UNACKED = 0;
uint8_t ACKED = 1;



//global variables
//states of connections
uint8_t SYN_SENT = 1;
uint8_t ESTABLISHED = 2;
uint8_t FIN_WAIT_1 = 3;
uint8_t CLOSE_WAIT = 4;
uint8_t FIN_WAIT_2 = 5;
uint8_t CLOSING = 6;
uint8_t LAST_ACK = 7;
uint8_t TIME_WAIT = 8;

uint8_t READING = 1;
uint8_t WRITING = 2;

uint32_t WAITING_LIMIT = 10000;
uint16_t BUFFER_SIZE = 50 * 1024; //51200

std::map<std::pair<int, int>, socket_params> socket_bindings;

//flags
uint8_t SYN = 2;
uint8_t ACK = 16;
uint8_t FIN = 1;

uint8_t header_length = 20;
uint32_t SEQ_NUM = 3456;
uint32_t UINT_MAX = 0xffffffff;
uint32_t TIMEOUT = 100000000;
TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
	 
}

void TCPAssignment::finalize()
{
	socket_bindings.clear();
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid); //, param.param1_int, param.param2_int);
		// param2 is unused, domain is always IPv4 (param1)
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		this->syscall_read(syscallUUID, pid, param.param1_int, (char *) param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int,(char *) param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr_in *>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr_in*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr_in *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr_in *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr_in *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}


void TCPAssignment::syscall_socket(UUID syscallUUID, int pid)
{
	std::pair <int, int> key;
	std::pair <std::pair<int, int>, struct socket_params> map_entry;

	int fd = createFileDescriptor(pid);
	if (fd < 0) //prob not needed
	{	
		returnSystemCall(syscallUUID, -1);
		return;
	}

	struct socket_params empty_socket;
	memset(&empty_socket, 0, sizeof(socket_params));

	empty_socket.read_buf = (char *) malloc(BUFFER_SIZE);
	if (empty_socket.read_buf == NULL)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	empty_socket.write_buf = (char *) malloc(BUFFER_SIZE);
	if (empty_socket.write_buf == NULL)
	{
		free(empty_socket.read_buf);
		returnSystemCall(syscallUUID, -1);
		return;
	}

	key.first = pid;
	key.second = fd;
	map_entry.first = key;
	map_entry.second = empty_socket;

	socket_bindings.insert(map_entry);

	returnSystemCall(syscallUUID, fd);
	return;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
	std::map<std::pair<int, int>, struct socket_params>::iterator it;
	std::pair <int, int> key;
	key.first = pid;
	key.second = fd;
	it = socket_bindings.find(key);
	if (it == socket_bindings.end()) // the key is not found
	{
		returnSystemCall(syscallUUID, -1); //actually the returned number doesn't matter
		return;
	}

	struct socket_params *socket = &(it->second);

	if (!socket->bound || socket->state == SYN_SENT)
	{
		if (socket_bindings.erase(key))
		{
			removeFileDescriptor(pid, fd);
		}
		returnSystemCall(syscallUUID, 0);
		return;
	}

	if (socket->passive)
	{
		struct listening_params *listen_struct = socket->listen_struct;
		struct waiting_connection *waiting_connection;

		for (uint32_t i = 0; i < WAITING_LIMIT; i++)
		{
			waiting_connection = listen_struct->waiting_list + i;
			if (waiting_connection->dest_addr && waiting_connection->dest_port)
			{
				if (waiting_connection->state == CLOSE_WAIT || waiting_connection->state == ESTABLISHED)
				{
					Packet *packet = this->allocatePacket(14 + 20 + 20);

					uint32_t net_src_addr = htonl(waiting_connection->src_addr);
					uint32_t net_dest_addr = htonl(waiting_connection->dest_addr);
					packet->writeData(14 + 4*3, &net_src_addr, 4); 
					packet->writeData(14 + 4*4, &net_dest_addr, 4);

					uint8_t buffer[20];
					memset(buffer, 0, 20);

					uint32_t net_src_port = htons(socket->src_port);
					uint32_t net_dest_port = htons(waiting_connection->dest_port);
					memcpy(buffer, &net_src_port, 2);
					memcpy(buffer + 2, &net_dest_port, 2);

					uint32_t seq_num = htonl(waiting_connection->seq_num);
					memcpy(buffer + 4, &seq_num, 4);

					waiting_connection->seq_num++;
					uint16_t new_flags = htons(0x5001);
					memcpy(buffer + 12, &new_flags, 2);

					uint16_t window = htons(0xc800);
					memcpy(buffer + 12 + 2, &window, 2);

					uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_src_addr, net_dest_addr, buffer, 20));							
					memcpy(buffer + 16, &checksum, 2);
					
					packet->writeData(14 + 20, buffer, 20);

					this->sendPacket("IPv4", packet);
					if (waiting_connection->state == CLOSE_WAIT)
					{
						waiting_connection->state = LAST_ACK;
					}
					if (waiting_connection->state == ESTABLISHED)
					{
						waiting_connection->state = FIN_WAIT_1;
					}
				}
			}
		}

		//close pending connections
		struct pending_connection *pending_connection;
		for (uint32_t i = 0; i < listen_struct->backlog; i++) 
		{ 
			pending_connection = listen_struct->pending_list + i;
			if (pending_connection->dest_addr && pending_connection->dest_port)
			{
				Packet *packet = this->allocatePacket(14 + 20 + 20);

				uint32_t net_src_addr = htonl(pending_connection->src_addr);
				uint32_t net_dest_addr = htonl(pending_connection->dest_addr);
				packet->writeData(14 + 4*3, &net_src_addr, 4); 
				packet->writeData(14 + 4*4, &net_dest_addr, 4);

				uint8_t buffer[20];
				memset(buffer, 0, 20);

				uint32_t net_src_port = htons(socket->src_port);
				uint32_t net_dest_port = htons(pending_connection->dest_port);
				memcpy(buffer, &net_src_port, 2);
				memcpy(buffer + 2, &net_dest_port, 2);

				uint32_t seq_num = htons(SEQ_NUM + 1);
				memcpy(buffer + 4, &seq_num, 4);

				uint16_t new_flags = htons(0x5001);
				memcpy(buffer + 12, &new_flags, 2);

				uint16_t window = htons(0xc800);
				memcpy(buffer + 12 + 2, &window, 2);

				uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_src_addr, net_dest_addr, buffer, 20));							
				memcpy(buffer + 16, &checksum, 2);
				
				packet->writeData(14 + 20, buffer, 20);

				this->sendPacket("IPv4", packet);

				for (uint32_t j = 0; j < WAITING_LIMIT; j++)
				{
					waiting_connection = listen_struct->waiting_list + j;
					if (!waiting_connection->dest_addr && !waiting_connection->dest_port)
					{
						listen_struct->waiting_count++;
						listen_struct->pending_count -= 1;
						waiting_connection->state = FIN_WAIT_1;
						waiting_connection->seq_num = SEQ_NUM + 2;
						waiting_connection->dest_addr = pending_connection->dest_addr;
						waiting_connection->dest_port = pending_connection->dest_port;
						waiting_connection->src_addr = pending_connection->src_addr;
						memset(pending_connection, 0 , sizeof(struct pending_connection));
						break;
					}
				}
			}
		}

		returnSystemCall(syscallUUID, 0); // idk, w/e
		return;
	}

	if (socket->state == ESTABLISHED && calculate_empty_space(socket) < BUFFER_SIZE)
	{
		socket->closing = true;
		returnSystemCall(syscallUUID, 0);
		return;
	}


	if (socket->state == ESTABLISHED || socket->state == CLOSE_WAIT)	
	{
		if (socket->state == ESTABLISHED)
		{
			socket->state = FIN_WAIT_1;
		}

		if (socket->state == CLOSE_WAIT)
		{
			socket->state = LAST_ACK;
		}

		Packet *packet = this->allocatePacket(14 + 20 + 20);

		uint32_t net_src_addr = htonl(socket->src_addr);

		packet->writeData(14 + 4*3, &net_src_addr, 4);

		uint32_t net_dest_addr = htonl(socket->dest_addr);
		packet->writeData(14 + 4*4, &net_dest_addr, 4);

		uint8_t buffer[20];
		memset(buffer, 0, 20);

		uint16_t net_src_port = htons(socket->src_port);
		memcpy(buffer, &net_src_port, 2);

		uint16_t net_dest_port = htons(socket->dest_port);
		memcpy(buffer + 2, &net_dest_port, 2);

		uint32_t seq_num = htonl(socket->seq_num);
		memcpy(buffer + 4, &seq_num, 4);

		socket->seq_num++;
		uint16_t flags = htons(0x5001);
		memcpy(buffer + 12, &flags, 2);

		uint16_t window = htons(0xc800);
		memcpy(buffer + 12 + 2, &window, 2);

		uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_src_addr, net_dest_addr, buffer, 20));							
		memcpy(buffer + 16, &checksum, 2);

		packet->writeData(14 + 20, buffer, 20);
		this->sendPacket("IPv4", packet);
		returnSystemCall(syscallUUID, 0); // idk, w/e
		return;
	}
	
	return;
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, char *given_buf, int count)
{
	std::pair <int, int> key;
	key.first = pid;
	key.second = fd;

	std::map<std::pair<int, int>, struct socket_params>::iterator it;
	it = socket_bindings.find(key);

	if (it == socket_bindings.end()) // the key is not found
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	struct socket_params *socket = &(it->second);
	uint16_t read_window = calculate_read_window(&socket->read_map, socket->last_byte_read);
	if (read_window > 0) //ready to return syscall
	{
		uint16_t buf_tail = BUFFER_SIZE - socket->last_byte_read;
		uint16_t bytes_to_put = read_window > count ? count : read_window;
		if (buf_tail < bytes_to_put)
		{
			memcpy(given_buf, socket->read_buf + socket->last_byte_read, buf_tail);
			memcpy(given_buf + buf_tail, socket->read_buf, bytes_to_put - buf_tail);
		}
		else
		{
			memcpy(given_buf, socket->read_buf + socket->last_byte_read, bytes_to_put);
		} 
		reflect_read(socket, bytes_to_put);
		socket->last_byte_read += bytes_to_put;
		socket->last_byte_read %= BUFFER_SIZE;
		socket->smallest_valid_seq_num += bytes_to_put;
		returnSystemCall(syscallUUID, bytes_to_put);
	}
	else
	{ //save context and wait for packets
		//read in bytes that are stored so far, especially for the case of full buffer
		socket->syscallUUID = syscallUUID;
		socket->mode = READING;
		socket->given_buf = given_buf;
		socket->count = count;
	}

	return;
}
void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, char *given_buf, int count)
{
	std::pair <int, int> key;
	key.first = pid;
	key.second = fd;

	std::map<std::pair<int, int>, struct socket_params>::iterator it;
	it = socket_bindings.find(key);

	if (it == socket_bindings.end()) // the key is not found
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	struct socket_params *socket = &(it->second);

	
	uint8_t buffer[20];
	memset(buffer, 0, 20);

	uint32_t net_src_addr = htonl(socket->src_addr);
	
	uint32_t net_dest_addr = htonl(socket->dest_addr);

	uint16_t net_src_port = htons(socket->src_port);
	memcpy(buffer, &net_src_port, 2);
	uint16_t net_dest_port = htons(socket->dest_port);
	memcpy(buffer + 2, &net_dest_port, 2);

	uint32_t seq_num = htonl(socket->seq_num);
	memcpy(buffer + 4, &seq_num, 4);

	uint32_t ack_num = htonl(socket->ack_num);
	memcpy(buffer + 8, &ack_num, 4);

	uint16_t flags = htons(0x5010);
	memcpy(buffer + 12, &flags, 2);

	uint16_t window = htons(BUFFER_SIZE - socket->read_window);
	memcpy(buffer + 12 + 2, &window, 2);

	 //write window before putting bytes in the buffer


	//handle case of count == 0
	if (count == 0)
	{
		Packet *packet = this->allocatePacket(14 + 20 + 20);
		packet->writeData(14 + 4*3, &net_src_addr, 4);
		packet->writeData(14 + 4*4, &net_dest_addr, 4);
		uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_src_addr, net_dest_addr, buffer, 20));							
		memcpy(buffer + 16, &checksum, 2);
		packet->writeData(14 + 20, buffer, 20);
		this->sendPacket("IPv4", packet);
		returnSystemCall(syscallUUID, 0);
	}
	else
	{
		uint16_t empty_space = calculate_empty_space(socket);
		if (empty_space >= count)
		{
			std::pair <uint32_t, write_mapping> write_map_entry;
			struct write_mapping mapping;
			mapping.size = count;
			mapping.seq_num = socket->seq_num;
			socket->seq_num += count;
			mapping.sent = false;
			mapping.buf_index = new_buf_index(socket);

			write_map_entry.first = mapping.seq_num + count;
			write_map_entry.second = mapping;

			socket->write_map.insert(write_map_entry);

			uint16_t buf_tail = BUFFER_SIZE - mapping.buf_index;
			memcpy(socket->write_buf + mapping.buf_index, given_buf, buf_tail > count ? count : buf_tail);
			if (count > buf_tail)
				memcpy(socket->write_buf, given_buf + buf_tail, count - buf_tail);
		
			
			returnSystemCall(syscallUUID, count);
		}
		else 
		{
			socket->mode = WRITING;
			socket->given_buf = given_buf;
			socket->syscallUUID = syscallUUID;
			socket->count = count;
		}

		sendall(socket);
	}
	return;
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr_in *addr, socklen_t len)
{
	std::pair <int, int> key;
	key.first = pid;
	key.second = fd;
	
	uint16_t net_dest_port = addr->sin_port;
	uint32_t net_dest_addr = addr->sin_addr.s_addr;

	uint16_t dest_port = ntohs(net_dest_port);
	uint32_t dest_addr = ntohl(net_dest_addr);

	std::map<std::pair<int, int>, struct socket_params>::iterator it;
	it = socket_bindings.find(key);

	struct socket_params *socket = &(it->second);

	if (it == socket_bindings.end()) // the key is not found
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	if (!socket->bound) { //implicit bind
		uint32_t ip_addr = dest_addr;
		Host *host = getHost();
		int port = host->getRoutingTable((uint8_t *) &ip_addr); 
		bool success = host->getIPAddr((uint8_t *) &ip_addr, port);


		if (!success) { //shouldn't happpen but just in case
			returnSystemCall(syscallUUID, -1);
			return;
		}

		bool *bitmap = (bool *) calloc(65536, sizeof(bool));

		std::map<std::pair<int, int>, struct socket_params>::iterator itr;
		for (itr = socket_bindings.begin(); itr != socket_bindings.end(); ++itr)
		{ // mark all ports which are taken
			if ((itr->second).src_addr == ip_addr && (itr->second).bound)
			{
				*(bitmap + (itr->second).src_port) = true;
			}
		}

		port = 0;
		for (uint32_t i = 1; i < 65536; i++) 
		{ //look for an empty port
			if (!(*(bitmap + i)))
			{
				port = i;
				break;
			}
		}

		free(bitmap);

		if (port == 0) { // reject in case all ports are taken
			returnSystemCall(syscallUUID, -1);
			return;
		}

		socket->src_addr = ntohl(ip_addr);
		socket->src_port = port;
		socket->bound = true;
	}

	socket->dest_addr = dest_addr;
	socket->dest_port = dest_port;
	socket->state = SYN_SENT;
	socket->syscallUUID = syscallUUID;
	socket->connecting = true;
	socket->seq_num = SEQ_NUM;

	Packet *packet = this->allocatePacket(14 + 20 + 20);
	uint8_t buffer[20];
	memset(buffer, 0, 20);

	uint32_t net_src_addr = htonl(socket->src_addr);
	packet->writeData(14 + 4*3, &net_src_addr, 4);

	packet->writeData(14 + 4*4, &net_dest_addr, 4); 

	uint16_t net_src_port = htons(socket->src_port);
	memcpy(buffer, &net_src_port, 2);
	memcpy(buffer + 2, &net_dest_port, 2);

	uint32_t seq_num = htonl(SEQ_NUM);
	memcpy(buffer + 4, &seq_num, 4);

	socket->seq_num++;
	uint16_t flags = htons(0x5002);
	memcpy(buffer + 12, &flags, 2);

	uint16_t window = htons(0xc800);
	memcpy(buffer + 12 + 2, &window, 2);

	uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_src_addr, net_dest_addr, buffer, 20));							
	memcpy(buffer + 16, &checksum, 2);

	char *payload = (char *) malloc(1 + sizeof(std::pair <int, int>));
	memset(payload, 2, 1);
	memcpy(payload + 1, &(it->first), sizeof(std::pair <int, int>));
	socket->timer = addTimer((void *) payload, TIMEOUT);

	packet->writeData(14 + 20, buffer, 20);
	this->sendPacket("IPv4", packet);
	return;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog)
{
	std::map<std::pair<int, int>, struct socket_params>::iterator it;
	std::pair <int, int> key;
	key.first = pid;
	key.second = fd;
	it = socket_bindings.find(key);

	if (it == socket_bindings.end()) // the key is not found
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}
	struct socket_params *socket = &(it->second);
	
	socket->passive = true;
	socket->listen_struct = (struct listening_params *) calloc(1, sizeof(struct listening_params));
	struct listening_params *listen_struct = socket->listen_struct;
	if (socket->listen_struct == NULL)
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}


	listen_struct->pending_list = (struct pending_connection *) calloc(backlog, sizeof(struct pending_connection));
	if (listen_struct->pending_list == NULL)
	{
		free(socket->listen_struct);
		returnSystemCall(syscallUUID, -1);
		return;
	}
	
	listen_struct->waiting_list = (struct waiting_connection *) calloc(WAITING_LIMIT, sizeof(struct waiting_connection));
	if (listen_struct->waiting_list == NULL)
	{
		free(socket->listen_struct);
		free(listen_struct->pending_list);
		returnSystemCall(syscallUUID, -1);
		return;
	}

	listen_struct->backlog = backlog;
	returnSystemCall(syscallUUID, 0);
	return;
}


void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr_in* addr, socklen_t *len) 
{
	
	std::map<std::pair<int, int>, struct socket_params>::iterator it;
	std::pair <int, int> key;


	key.first = pid;
	key.second = fd;
	it = socket_bindings.find(key); // find the listening socket
	

	if (it == socket_bindings.end() || !(it->second).passive) // the key is not found
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	struct socket_params *socket = &(it->second);
	struct listening_params *listen_struct = socket->listen_struct;

	if (listen_struct->waiting_count > 0)
	{	
		uint32_t i;
		for (i = 0; i < WAITING_LIMIT; i++)
		{
			struct waiting_connection *waiting_connection = listen_struct->waiting_list + i;
			if (waiting_connection->dest_addr)
			{
				std::pair <int, int> new_key;
				int new_fd = createFileDescriptor(pid);

				if (new_fd < 0) 
				{
					returnSystemCall(syscallUUID, -1);
					return;
				}

				new_key.first = pid;
				new_key.second = new_fd;

				struct socket_params accept_socket;
				memset(&accept_socket, 0, sizeof(struct socket_params));

				accept_socket.read_buf = (char *) malloc(BUFFER_SIZE);
				if (accept_socket.read_buf == NULL)
				{
					removeFileDescriptor(pid, new_fd);
					returnSystemCall(syscallUUID, -1);
					return;
				}

				accept_socket.write_buf = (char *) malloc(BUFFER_SIZE);
				if (accept_socket.write_buf == NULL)
				{
					removeFileDescriptor(pid, new_fd);
					free(accept_socket.read_buf);
					returnSystemCall(syscallUUID, -1);
					return;
				}

				accept_socket.syscallUUID = syscallUUID;
				accept_socket.state = waiting_connection->state;//ESTABLISHED; //established
				accept_socket.bound = true;
				accept_socket.src_addr = waiting_connection->src_addr;
				accept_socket.src_port = socket->src_port;
				accept_socket.dest_addr = waiting_connection->dest_addr;
				accept_socket.dest_port = waiting_connection->dest_port;
				accept_socket.seq_num = waiting_connection->seq_num; //SEQ_NUM + 1;
				accept_socket.peer_window = waiting_connection->peer_window;
				accept_socket.ack_num = waiting_connection->ack_num;
				accept_socket.last_ack_received = waiting_connection->last_ack_received;
				accept_socket.smallest_valid_seq_num = accept_socket.ack_num;

				std::pair <std::pair<int, int>, struct socket_params> map_entry;
				map_entry.first = new_key;
				map_entry.second = accept_socket;
				socket_bindings.insert(map_entry);

				memset(waiting_connection, 0, sizeof(struct waiting_connection));
				(socket->listen_struct)->waiting_count -= 1;

				struct sockaddr_in dummy_addr;
				memset(&dummy_addr, 0, sizeof(dummy_addr));
				dummy_addr.sin_family = AF_INET;
				dummy_addr.sin_port = htons(accept_socket.dest_port);
				dummy_addr.sin_addr.s_addr = htonl(accept_socket.dest_addr);

				if (sizeof(dummy_addr) < *len)
				{
					memcpy(addr, &dummy_addr, sizeof(dummy_addr));
				} 
				else 
				{
					memcpy(addr, &dummy_addr, *len);
				}

				*len = sizeof(dummy_addr);

				returnSystemCall(syscallUUID, new_fd);
				return;
			}
		}
	} 
	//no established connections to consume
	listen_struct->syscallUUID = syscallUUID; 
	listen_struct->addr = addr; // save the accept context in the listen socket
	listen_struct->len = len; // use it when a connection is established
	listen_struct->pid = pid;
	return;
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr_in * addr, socklen_t len)
{	
	std::map<std::pair<int, int>, struct socket_params>::iterator it;
	struct socket_params *socket;

	uint16_t src_port = ntohs(addr->sin_port);
	uint32_t src_addr = ntohl(addr->sin_addr.s_addr);

	for (it = socket_bindings.begin(); it != socket_bindings.end(); ++it)
	{ // make sure that the addr/port are not bound yet
		socket = &(it->second);
		if (((socket->src_port == src_port) && (socket->src_addr == src_addr || socket->src_addr == INADDR_ANY)) && socket->bound)
		{
			returnSystemCall(syscallUUID, -1);
			break;
		}
	}

	std::pair <int, int> key;
	key.first = pid;
	key.second = fd;
	it = socket_bindings.find(key);

	if (it == socket_bindings.end()) // the key is not found
	{
		returnSystemCall(syscallUUID, -1);
		return;
	}

	socket = &(it->second);

	if (socket->bound)  
	{ // make sure it hasn't been bound yet
		returnSystemCall(syscallUUID, -1);
		return;
	}

	socket->src_addr = src_addr; // if everything is ok,
	socket->src_port = src_port; // bind the socket
	socket->bound = true;

	returnSystemCall(syscallUUID, 0);
	return;
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr_in *addr, socklen_t *len)
{
	std::map<std::pair<int, int>, struct socket_params>::iterator it;
	std::pair <int, int> key;
	
	key.first = pid;
	key.second = fd;
	it = socket_bindings.find(key);

	if (it == socket_bindings.end() || !(it->second).bound) 
	{ // the key is not found or the socket hasn't been bound
		returnSystemCall(syscallUUID, -1);
		return;
	}

	struct sockaddr_in dummy_addr;
	memset(&dummy_addr, 0, sizeof(dummy_addr));
	dummy_addr.sin_family = AF_INET;
	dummy_addr.sin_port = htons((it->second).src_port);
	dummy_addr.sin_addr.s_addr = htonl((it->second).src_addr);

	if (sizeof(dummy_addr) < *len)
	{
		memcpy(addr, &dummy_addr, sizeof(dummy_addr));
	} 
	else 
	{
		memcpy(addr, &dummy_addr, *len);
	}

	*len = sizeof(dummy_addr);
	returnSystemCall(syscallUUID, 0);
	return;
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr_in *addr, socklen_t *len)
{
	std::map<std::pair<int, int>, struct socket_params>::iterator it;
	std::pair <int, int> key;
	key.first = pid;
	key.second = fd;
	it = socket_bindings.find(key);

	if (it == socket_bindings.end() || !(it->second).bound) 
	{ // the key is not found or the socket hasn't been bound
		returnSystemCall(syscallUUID, -1);
		return;
	}

	struct socket_params *socket = &(it->second);

	struct sockaddr_in dummy_addr;
	dummy_addr.sin_family = AF_INET;
	dummy_addr.sin_port = htons(socket->dest_port);
	dummy_addr.sin_addr.s_addr = htonl(socket->dest_addr); 

	if (sizeof(dummy_addr) < *len)
	{
		memcpy(addr, &dummy_addr, sizeof(dummy_addr));
	} 
	else 
	{
		memcpy(addr, &dummy_addr, *len);
	}

	*len = sizeof(dummy_addr);
	returnSystemCall(syscallUUID, 0);
	return;
}


void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	uint8_t flags;
	uint32_t net_sender_addr;
	uint16_t net_sender_port;
	uint32_t net_receiver_addr;
	uint16_t net_receiver_port;

	std::map<std::pair<int, int>, struct socket_params>::iterator it;
	packet->readData(14 + 20 + 4*3 + 1, &flags, 1);

	packet->readData(14 + 4*3, &net_sender_addr, 4); //sender addr 
	packet->readData(14 + 4*4, &net_receiver_addr, 4); //receiver addr
	packet->readData(14 + 20, &net_sender_port, 2); //sender port
	packet->readData(14 + 20 + 2, &net_receiver_port, 2); //receiver port


	uint16_t sender_port = ntohs(net_sender_port);
	uint32_t sender_addr = ntohl(net_sender_addr);
	uint32_t receiver_addr = ntohl(net_receiver_addr);
	uint16_t receiver_port = ntohs(net_receiver_port);


	ssize_t packet_size = packet->getSize() - 34;
	uint8_t checksum_buffer[packet_size];
	packet->readData(14 + 20, checksum_buffer, packet_size);
	uint16_t inc_checksum = htons(~NetworkUtil::tcp_sum(net_sender_addr, net_receiver_addr, checksum_buffer, packet_size));
	
	if (inc_checksum != 0) //&& inc_checksum != 0xFFFF)
	{
		this->freePacket(packet);
		return;
	}


	if (flags & SYN) // handshake
	{
		if (flags & ACK) //client received SYN ACK
		{
			for (it = socket_bindings.begin(); it != socket_bindings.end(); ++it)
			{
				struct socket_params *socket = &(it->second);

				if (socket->bound && socket->src_addr == receiver_addr && socket->src_port == receiver_port && socket->dest_addr == sender_addr && socket->dest_port == sender_port /*&& socket->state == SYN_SENT*/ && !socket->passive)
				{//found the client's socket
					cancelTimer(socket->timer);

					socket->state = ESTABLISHED;
					packet->readData(14 + 20 + 14, &socket->peer_window, 2);
					socket->peer_window = ntohs(socket->peer_window);
					
					Packet *response = this->clonePacket(packet);
					response->writeData(14 + 4*3, &net_receiver_addr, 4); 
					response->writeData(14 + 4*4, &net_sender_addr, 4); 

					packet->readData(14 + 20 + 8, &socket->last_ack_received, 4);
					socket->last_ack_received = ntohl(socket->last_ack_received);

					uint8_t buffer[20];
					memset(buffer, 0, 20);

					memcpy(buffer, &net_receiver_port, 2);
					memcpy(buffer + 2, &net_sender_port, 2);

					uint32_t seq_num = htonl(socket->seq_num);
					memcpy(buffer + 4, &seq_num, 4);

					uint32_t ack_num;
					packet->readData(14 + 20 + 4, &ack_num, 4);
					ack_num = ntohl(ack_num);
					ack_num++;
					socket->ack_num = ack_num;
					socket->smallest_valid_seq_num = ack_num;
					ack_num = htonl(ack_num);
					memcpy(buffer + 8, &ack_num, 4);

					uint16_t new_flags = htons(0x5010);
					memcpy(buffer + 12, &new_flags, 2);

					uint16_t window = htons(0xc800);
					memcpy(buffer + 12 + 2, &window, 2);

					uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_receiver_addr, net_sender_addr, buffer, 20));							
					memcpy(buffer + 16, &checksum, 2);
					
					response->writeData(14 + 20, buffer, 20);
					this->sendPacket("IPv4", response);

					if (socket->connecting)
					{
						socket->connecting = false;
						returnSystemCall(socket->syscallUUID, 0);
					}
					this->freePacket(packet);
					return;
				}					
			}
			this->freePacket(packet); // just free the packet of no such socket is found
			return;
		} 
		else //server received SYN
		{

			for (it = socket_bindings.begin(); it != socket_bindings.end(); ++it)
			{ // look for the listening socket

				struct socket_params *socket = &(it->second);

				if (socket->bound && socket->passive && socket->src_port == receiver_port && (socket->src_addr == receiver_addr || socket->src_addr == INADDR_ANY))
				{ // found the listening socket
					struct listening_params *listen_struct = socket->listen_struct;

					if (listen_struct->backlog == listen_struct->pending_count)
					{ //if too many connections are pending
						this->freePacket(packet);
						return;
					}
					
					struct pending_connection *pending_connection;
					for (uint32_t i = 0; i < listen_struct->backlog; i++)
					{
						pending_connection = listen_struct->pending_list + i;
						if (!pending_connection->dest_addr)
						{//the slot is empty
							listen_struct->pending_count += 1;
							pending_connection->src_addr = receiver_addr;
							pending_connection->dest_addr = sender_addr;
							pending_connection->dest_port = sender_port;

							Packet *response = this->clonePacket(packet);

							response->writeData(14 + 4*3, &net_receiver_addr, 4);
							response->writeData(14 + 4*4, &net_sender_addr, 4);

							uint8_t tcp_header_buffer[20];
							memset(tcp_header_buffer, 0, 20);
							memcpy(tcp_header_buffer, &net_receiver_port, 2);
							memcpy(tcp_header_buffer + 2, &net_sender_port, 2);
							
							uint32_t seq_num = htonl(SEQ_NUM);
							memcpy(tcp_header_buffer + 4, &seq_num, 4);

							uint32_t ack_num;
							packet->readData(14 + 20 + 4, &ack_num, 4);
							ack_num = ntohl(ack_num);
							ack_num++;
							pending_connection->ack_num = ack_num;
							ack_num = htonl(ack_num);
							memcpy(tcp_header_buffer + 8, &ack_num, 4);

							uint16_t new_flags = htons(0x5012);

							memcpy(tcp_header_buffer + 12, &new_flags, 2);
							
							uint16_t window = htons(0xc800);
							memcpy(tcp_header_buffer + 12 + 2, &window, 2);

							uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_receiver_addr, net_sender_addr, tcp_header_buffer, 20));							
							memcpy(tcp_header_buffer + 16, &checksum, 2);

							response->writeData(14 + 20, tcp_header_buffer, 20);

							char *payload = (char *) malloc(5 + sizeof(std::pair <int, int>));
							memset(payload, 3, 1);
							memcpy(payload + 1, &i, 4);
							memcpy(payload + 5, &(it->first), sizeof(std::pair <int, int>));
							pending_connection->timer = addTimer((void *) payload, TIMEOUT);

							this->sendPacket("IPv4", response);
							this->freePacket(packet);
							return;
						}
					}
				}
			}
			this->freePacket(packet);
			return; // just in case
		}
	}

	if (flags & FIN)
	{	
		for (it = socket_bindings.begin(); it != socket_bindings.end(); ++it)
		{
			struct socket_params *socket = &(it->second);
			if (false && socket->bound && !socket->passive && socket->src_port == receiver_port && (socket->src_addr == receiver_addr || socket->src_addr == INADDR_ANY) && socket->dest_addr == sender_addr && socket->dest_port == sender_port)
			{
				Packet *response = this->clonePacket(packet);
				response->writeData(14 + 4*3, &net_receiver_addr, 4); 
				response->writeData(14 + 4*4, &net_sender_addr, 4);

				uint8_t buffer[20];
				memset(buffer, 0, 20);

				memcpy(buffer, &net_receiver_port, 2);
				memcpy(buffer + 2, &net_sender_port, 2);

				uint32_t seq_num = htonl(socket->seq_num);
				memcpy(buffer + 4, &seq_num, 4);

				uint32_t ack_num;
				packet->readData(14 + 20 + 4, &ack_num, 4);
				ack_num = ntohl(ack_num);
				ack_num++;
				socket->ack_num = ack_num;
				ack_num = htonl(ack_num);
				memcpy(buffer + 8, &ack_num, 4);

				uint16_t new_flags = htons(0x5010);
				memcpy(buffer + 12, &new_flags, 2);

				uint16_t window = htons(0xc800);
				memcpy(buffer + 12 + 2, &window, 2);

				uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_receiver_addr, net_sender_addr, buffer, 20));							
				memcpy(buffer + 16, &checksum, 2);
				
				response->writeData(14 + 20, buffer, 20);

				this->sendPacket("IPv4", response);
				this->freePacket(packet);

				if (socket->state == FIN_WAIT_2 || (socket->state == FIN_WAIT_1 && (flags & ACK)))
				{
					socket->state = TIME_WAIT;
					char *key = (char *) malloc(1 + sizeof(std::pair <int, int>));
					memset(key, 1, 1);
					memcpy(key + 1, &(it->first), sizeof(std::pair <int, int>));
					addTimer((void *) key, 800000);
				}
				else if (socket->state == FIN_WAIT_1)
				{
					socket->state = CLOSING;
				} 
				else if (socket->state == ESTABLISHED)
				{
					socket->state = CLOSE_WAIT;
				}
				return;
			}
		}
		// in case no such connected/accept socket, look for the context in waiitng connections
		for (it = socket_bindings.begin(); it != socket_bindings.end(); ++it)
		{
			struct socket_params *socket = &(it->second);

			if(socket->passive && socket->bound && (socket->src_addr == receiver_addr || socket->src_addr == INADDR_ANY) && socket->src_port == receiver_port)
			{
				struct listening_params *listen_struct = socket->listen_struct;
				struct waiting_connection *waiting_connection;

				for (uint32_t i = 0; i < WAITING_LIMIT; i++)
				{
					waiting_connection = listen_struct->waiting_list + i;
					if (waiting_connection->dest_addr == sender_addr && waiting_connection->dest_port == sender_port)
					{
						Packet *response = this->clonePacket(packet);
						response->writeData(14 + 4*3, &net_receiver_addr, 4); 
						response->writeData(14 + 4*4, &net_sender_addr, 4);

						uint8_t buffer[20];
						memset(buffer, 0, 20);

						memcpy(buffer, &net_receiver_port, 2);
						memcpy(buffer + 2, &net_sender_port, 2);

						uint32_t seq_num = htonl(waiting_connection->seq_num);
						memcpy(buffer + 4, &seq_num, 4);

						uint32_t ack_num;
						packet->readData(14 + 20 + 4, &ack_num, 4);
						ack_num = ntohl(ack_num);
						ack_num++;
						ack_num = htonl(ack_num);
						memcpy(buffer + 8, &ack_num, 4);

						uint16_t new_flags = htons(0x5010);
						memcpy(buffer + 12, &new_flags, 2);

						uint16_t window = htons(0xc800);
						memcpy(buffer + 12 + 2, &window, 2);

						uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_receiver_addr, net_sender_addr, buffer, 20));							
						memcpy(buffer + 16, &checksum, 2);
						
						response->writeData(14 + 20, buffer, 20);

						this->sendPacket("IPv4", response);
						this->freePacket(packet);


						if (waiting_connection->state == FIN_WAIT_2 || (waiting_connection->state == FIN_WAIT_1 && (flags & ACK)))
						{
							waiting_connection->state = TIME_WAIT;
							char *key = (char *) malloc(5 + sizeof(std::pair <int, int>));
							memset(key, 0, 1); // not socket
							memcpy(key + 1, &i, 4);
							memcpy(key + 5, &(it->first), sizeof(std::pair <int, int>));
							addTimer((void *) key, 800000);
						}
						else if (waiting_connection->state == FIN_WAIT_1)
						{
							waiting_connection->state = CLOSING;
						} 
						else if (waiting_connection->state == ESTABLISHED)
						{
							waiting_connection->state = CLOSE_WAIT;
						}
						return;
					}
				}
			}
		}

		this->freePacket(packet); 
		return;
	}




	//make sure this is the last if !!!
	if (flags & ACK) // 3rd step of handshaking for the server for now, prob also case for data transferring
	{ //also in case of transitioning to FIN_WAIT_2 or CLOSED
		for (it = socket_bindings.begin(); it != socket_bindings.end(); ++it)
		{	//look for exact matches first
			struct socket_params *socket = &(it->second);
			if (socket->bound && socket->src_port == receiver_port && (socket->src_addr == receiver_addr || socket->src_addr == INADDR_ANY) && socket->dest_addr == sender_addr && socket->dest_port == sender_port)
			{

				if (socket->state == FIN_WAIT_1)
				{
					socket->state = FIN_WAIT_2;
					this->freePacket(packet);
					return;
				}
				else if (socket->state == LAST_ACK)
				{
					removeFileDescriptor((it->first).first, (it->first).second);
					socket_bindings.erase(it->first);
					this->freePacket(packet);
					return;
				}
				else if (socket->state == CLOSING)
				{
					socket->state = TIME_WAIT;
					char *key = (char *) malloc(1 + sizeof(std::pair <int, int>));
					memset(key, 1, 1);
					memcpy(key + 1, &(it->first), sizeof(std::pair <int, int>));
					addTimer((void *) key, 800000);
					this->freePacket(packet);
					return;
				}
				else if (socket->state == ESTABLISHED || socket->state == CLOSE_WAIT)
				{
					uint32_t received_seq_num;
					packet->readData(14 + 20 + 4, &received_seq_num, 4);
					received_seq_num = ntohl(received_seq_num);

					size_t data_length = packet->getSize() - 54;

					// the packet is outside of current scope
					if ((socket->smallest_valid_seq_num > received_seq_num && !(UINT_MAX - socket->smallest_valid_seq_num < 30000 && received_seq_num < UINT_MAX / 2)) && data_length > 0) 
					{
						uint8_t buffer[20];
						memset(buffer, 0, 20);

						memcpy(buffer, &net_receiver_port, 2);
						memcpy(buffer + 2, &net_sender_port, 2);

						uint32_t seq_num = htonl(socket->seq_num);
						memcpy(buffer + 4, &seq_num, 4);

						uint32_t ack_num = calculate_ack_num(socket);
						// ack_num = htonl(socket->ack_num);
						memcpy(buffer + 8, &ack_num, 4);

						uint16_t new_flags = htons(0x5010);
						memcpy(buffer + 12, &new_flags, 2);

						uint16_t window = htons(BUFFER_SIZE - calculate_buffer_bytes(&socket->read_map));
						memcpy(buffer + 12 + 2, &window, 2);

						Packet *response = this->allocatePacket(54);
						response->writeData(14 + 4*3, &net_receiver_addr, 4); 
						response->writeData(14 + 4*4, &net_sender_addr, 4);
						uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_receiver_addr, net_sender_addr, buffer, 20));
						memcpy(buffer + 16, &checksum, 2);
						response->writeData(14 + 20, buffer, 20);
						this->sendPacket("IPv4", response);
						this->freePacket(packet);
						return;
					}
					
					uint32_t ack_num;
					if (data_length > 0)
					{
						uint16_t start_index = socket->last_byte_read;
						if (UINT_MAX - socket->smallest_valid_seq_num < 30000 && received_seq_num < UINT_MAX / 2)
						{
							start_index += (UINT_MAX - socket->smallest_valid_seq_num) + received_seq_num + 1;
						}
						else
						{
							start_index += received_seq_num - socket->smallest_valid_seq_num;
						}
						start_index %= BUFFER_SIZE;

						uint16_t buf_tail = BUFFER_SIZE - start_index;
						packet->readData(54, socket->read_buf + start_index, buf_tail > data_length ? data_length : buf_tail);
						if (data_length > buf_tail)
						{
							packet->readData(54 + buf_tail, socket->read_buf, data_length - buf_tail); // I assume buffer can't be overflown due to recv window
						}
						
						std::pair <uint16_t, read_mapping> read_map_entry;
						read_map_entry.first = start_index;

						struct read_mapping mapping;
						mapping.ack_num = received_seq_num + data_length;
						mapping.size = data_length;
						read_map_entry.second = mapping;

						socket->read_map.insert(read_map_entry);

						ack_num = calculate_ack_num(socket);

						uint16_t read_window = calculate_read_window(&socket->read_map, socket->last_byte_read);
						if (socket->mode == READING && read_window > 0)
						{
							// printf("read_window: %d\n", read_window);
							// printf("buffer_bytes: %d\n", calculate_buffer_bytes(&socket->read_map));
							uint16_t bytes_to_put = read_window > socket->count ? socket->count : read_window;
							uint16_t buf_tail = BUFFER_SIZE - socket->last_byte_read;
							if (buf_tail < bytes_to_put)
							{
								memcpy(socket->given_buf, socket->read_buf + socket->last_byte_read, buf_tail);
								memcpy(socket->given_buf + buf_tail, socket->read_buf, bytes_to_put - buf_tail);
							}
							else
							{
								memcpy(socket->given_buf, socket->read_buf + socket->last_byte_read, bytes_to_put);
							}

							reflect_read(socket, bytes_to_put);
							socket->last_byte_read += bytes_to_put;
							socket->last_byte_read %= BUFFER_SIZE;
							socket->smallest_valid_seq_num += bytes_to_put;

							socket->mode = 0;
							socket->count = 0;
							returnSystemCall(socket->syscallUUID, bytes_to_put);
						}
					}

					//return ACK
					

					uint32_t received_ack;
					packet->readData(14 + 20 + 8, &received_ack, 4);
					received_ack = ntohl(received_ack);

					if (socket->last_ack_received == received_ack)
					{
						socket->duplicate_count++;
					}	
					else
					{
						socket->duplicate_count = 0;
						socket->fast_retransmitted = false;
						if (socket->timer_set)
						{
							cancelTimer(socket->timer);
							socket->timer_set = false;
						}
					}

					socket->last_ack_received = received_ack;


					if (data_length > 0)
					{
						Packet *response = this->allocatePacket(54);
						response->writeData(14 + 4*3, &net_receiver_addr, 4); 
						response->writeData(14 + 4*4, &net_sender_addr, 4);

						uint8_t buffer[20];
						memset(buffer, 0, 20);
						memcpy(buffer, &net_receiver_port, 2);
						memcpy(buffer + 2, &net_sender_port, 2);
						uint32_t seq_num = htonl(socket->seq_num);
						memcpy(buffer + 4, &seq_num, 4);

						socket->ack_num = ntohl(ack_num);
		
						memcpy(buffer + 8, &ack_num, 4);

						uint16_t new_flags = htons(0x5010);
						memcpy(buffer + 12, &new_flags, 2);

						uint16_t window = htons(BUFFER_SIZE - calculate_buffer_bytes(&socket->read_map));
						memcpy(buffer + 12 + 2, &window, 2);


						uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_receiver_addr, net_sender_addr, buffer, 20));							
						memcpy(buffer + 16, &checksum, 2);
						response->writeData(14 + 20, buffer, 20);
						this->sendPacket("IPv4", response);
						this->freePacket(packet);
					}

					clean_map(socket);

					if (socket->duplicate_count >= 3 && !socket->fast_retransmitted)
					{
						unsend(socket);
						socket->fast_retransmitted = true;
					}
					sendall(socket);

					uint16_t empty_space = calculate_empty_space(socket);
					if (socket->mode == WRITING && empty_space >= socket->count)
					{
						std::pair <uint32_t, write_mapping> write_map_entry;
						struct write_mapping mapping;
						mapping.size = socket->count;
						mapping.seq_num = socket->seq_num;
						socket->seq_num += socket->count;
						mapping.sent = false;
						mapping.buf_index = new_buf_index(socket);

						write_map_entry.first = mapping.seq_num + socket->count;
						write_map_entry.second = mapping;
						socket->write_map.insert(write_map_entry);

						uint16_t buf_tail = BUFFER_SIZE - mapping.buf_index;

						memcpy(socket->write_buf + mapping.buf_index, socket->given_buf, buf_tail > socket->count ? socket->count : buf_tail);
						if (socket->count > buf_tail)
							memcpy(socket->write_buf, socket->given_buf + buf_tail, socket->count - buf_tail);

						socket->mode = 0;
						returnSystemCall(socket->syscallUUID, socket->count);
					}

					empty_space = calculate_empty_space(socket);
					if (socket->closing && empty_space == BUFFER_SIZE)
					{
						Packet *close_packet = this->allocatePacket(14 + 20 + 20);
						close_packet->writeData(14 + 4*3, &net_receiver_addr, 4); 
						close_packet->writeData(14 + 4*4, &net_sender_addr, 4);

						uint8_t close_buffer[20];
						memset(close_buffer, 0, 20);

						memcpy(close_buffer, &net_receiver_port, 2);

						memcpy(close_buffer + 2, &net_sender_port, 2);

						uint32_t seq_num = htonl(socket->seq_num);
						memcpy(close_buffer + 4, &seq_num, 4);

						socket->seq_num++;
						uint16_t flags = htons(0x5001);
						memcpy(close_buffer + 12, &flags, 2);

						uint16_t window = htons(BUFFER_SIZE - socket->read_window);
						memcpy(close_buffer + 12 + 2, &window, 2);

						uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_receiver_port, net_sender_port, close_buffer, 20));							
						memcpy(close_buffer + 16, &checksum, 2);

						close_packet->writeData(14 + 20, close_buffer, 20);
						this->sendPacket("IPv4", close_packet);
					}

					return;
				}
				else
				{
					this->freePacket(packet);
					return;
				}
			}
		}

		//if not found look for a listening socket
		for (it = socket_bindings.begin(); it != socket_bindings.end(); ++it)
		{
			struct socket_params *socket = &(it->second);

			if (socket->bound && socket->passive && socket->src_port == receiver_port && (socket->src_addr == receiver_addr || socket->src_addr == INADDR_ANY))
			{	
				struct listening_params *listen_struct = socket->listen_struct;
				struct pending_connection *pending_connection = listen_struct->pending_list;
				for (uint32_t i = 0; i < listen_struct->backlog; i++)
				{
					pending_connection = listen_struct->pending_list + i;
					if (pending_connection->dest_addr == sender_addr && pending_connection->dest_port == sender_port)
					{
						listen_struct->pending_count -= 1;
						cancelTimer(pending_connection->timer);


						if (listen_struct->syscallUUID) //there's a blocked accept
						{
							int fd = createFileDescriptor(listen_struct->pid);
							if (fd < 0) 
							{
								returnSystemCall(listen_struct->syscallUUID, -1);
								this->freePacket(packet);
								return;
							}
							std::pair <int, int> key;
							key.first = listen_struct->pid;
							key.second = fd;
							struct socket_params accept_socket;
							memset(&accept_socket, 0, sizeof(struct socket_params));

							accept_socket.read_buf = (char *) malloc(BUFFER_SIZE);
							if (accept_socket.read_buf == NULL)
							{
								removeFileDescriptor(listen_struct->pid, fd);
								returnSystemCall(listen_struct->syscallUUID, -1);
								this->freePacket(packet);
								return;
							}

							accept_socket.write_buf = (char *) malloc(BUFFER_SIZE);
							if (accept_socket.write_buf == NULL)
							{
								removeFileDescriptor(listen_struct->pid, fd);
								free(accept_socket.read_buf);
								returnSystemCall(listen_struct->syscallUUID, -1);
								this->freePacket(packet);
								return;
							}

							accept_socket.syscallUUID = listen_struct->syscallUUID;
							accept_socket.state = ESTABLISHED; //established
							accept_socket.bound = true;
							accept_socket.src_addr = receiver_addr;
							accept_socket.src_port = socket->src_port;
							accept_socket.dest_addr = sender_addr;
							accept_socket.dest_port = sender_port;

							packet->readData(14 + 20 + 8, &accept_socket.last_ack_received, 4);
							accept_socket.last_ack_received = ntohl(accept_socket.last_ack_received);

							packet->readData(14 + 20 + 14, &accept_socket.peer_window, 2);
							accept_socket.peer_window = ntohs(accept_socket.peer_window);

							uint32_t seq_num;
							packet->readData(14 + 20 + 8, &seq_num, 4);
							accept_socket.seq_num = ntohl(seq_num);
							accept_socket.ack_num = pending_connection->ack_num;
							accept_socket.smallest_valid_seq_num = accept_socket.ack_num;


							std::pair <std::pair<int, int>, struct socket_params> map_entry;
							map_entry.first = key;
							map_entry.second = accept_socket;
							socket_bindings.insert(map_entry);


							struct sockaddr_in dummy_addr;
							memset(&dummy_addr, 0, sizeof(dummy_addr));
							dummy_addr.sin_family = AF_INET;
							dummy_addr.sin_port = htons(accept_socket.dest_port);
							dummy_addr.sin_addr.s_addr = htonl(accept_socket.dest_addr);

							if (sizeof(dummy_addr) < *(listen_struct->len))
							{
								memcpy(listen_struct->addr, &dummy_addr, sizeof(dummy_addr));
							} 
							else 
							{
								memcpy(listen_struct->addr, &dummy_addr, *(listen_struct->len));
							}

							*(listen_struct->len) = sizeof(dummy_addr);

							this->freePacket(packet);
							memset(pending_connection, 0, sizeof(struct pending_connection));
							returnSystemCall(listen_struct->syscallUUID, fd);
							return;
						}
						else // no blocked accept, save the context in the waiting list
						{
							if (listen_struct->waiting_count >= WAITING_LIMIT)
							{
								this->freePacket(packet);
								return;
							}
							listen_struct->waiting_count += 1;

							struct waiting_connection *waiting_connection = listen_struct->waiting_list;
							for (uint32_t i = 0; i < WAITING_LIMIT; i++)
							{
								waiting_connection = waiting_connection + i;
								if (waiting_connection->dest_addr == 0) //empty slot
								{
									waiting_connection->src_addr = receiver_addr;
									waiting_connection->dest_addr = sender_addr;
									waiting_connection->dest_port = sender_port;
									
									packet->readData(14 + 20 + 14, &waiting_connection->peer_window, 2);
									waiting_connection->peer_window = ntohs(waiting_connection->peer_window);

									packet->readData(14 + 20 + 8, &waiting_connection->last_ack_received, 4);
									waiting_connection->last_ack_received = ntohl(waiting_connection->last_ack_received);

									uint32_t seq_num;
									packet->readData(14 + 20 + 8, &seq_num, 4);
									waiting_connection->seq_num = ntohl(seq_num);
									waiting_connection->state = ESTABLISHED;
									waiting_connection->ack_num = pending_connection->ack_num;
									this->freePacket(packet);
									return;
								}
							}
						}
					}
				}
				//if not found in pending look in waiting
				for (uint32_t i = 0; i < WAITING_LIMIT; i++)
				{
					struct waiting_connection *waiting_connection = listen_struct->waiting_list + i;
					if (waiting_connection->dest_addr == sender_addr && waiting_connection->dest_port == sender_port)
					{	
						if (waiting_connection->state == LAST_ACK)
						{
							memset(waiting_connection, 0, sizeof(struct waiting_connection));
							listen_struct->waiting_count--;
							if (listen_struct->waiting_count == 0)
							{
								free(listen_struct->waiting_list);
								free(listen_struct->pending_list);
								free(listen_struct);
								removeFileDescriptor((it->first).first, (it->first).second);
								socket_bindings.erase(it->first);
								this->freePacket(packet);
								return;
							}
						}
						if (waiting_connection->state == FIN_WAIT_1)
						{
							waiting_connection->state = FIN_WAIT_2;
							this->freePacket(packet);
							return;
						}
						if (waiting_connection->state == CLOSING)
						{
							waiting_connection->state = TIME_WAIT;
							char *key = (char *) malloc(5 + sizeof(std::pair <int, int>));
							memset(key, 0, 1); // not socket
							memcpy(key + 1, &i, 4);
							memcpy(key + 5, &(it->first), sizeof(std::pair <int, int>));
							addTimer((void *) key, 800000);
							this->freePacket(packet);
							return;
						}
					}
				}
			}
		}
	}
}

uint16_t TCPAssignment::calculate_read_window(std::map<uint16_t, read_mapping> *read_map, uint16_t buf_index)
{
	uint16_t consequent_bytes = 0;
	std::map<uint16_t, read_mapping>::iterator it;
	uint16_t last_byte_read = buf_index;
	bool started = false;

	while (true) 
	{
		it = read_map->find(buf_index);
		if (it == read_map->end() || (it->first == last_byte_read && started))
			return consequent_bytes;

		uint16_t size = it->second.size;
		started = true;
		consequent_bytes += size;
		buf_index += size; 
		buf_index %= BUFFER_SIZE;
	}
	// return consequent_bytes;
}

void TCPAssignment::reflect_read(struct socket_params *socket, uint16_t bytes_read)
{
	std::map<uint16_t, read_mapping>::iterator it;
	std::map<uint16_t, read_mapping> *read_map = &socket->read_map;
	uint16_t bytes_removed = 0;
	uint16_t buf_index = socket->last_byte_read;


	while (true) 
	{
		it = read_map->find(buf_index);
		if (it == read_map->end())
		{	
			printf("reflect went wrong\n");
			break;
		}

		uint16_t size = it->second.size;
		if (bytes_removed + size <= bytes_read)
		{
			bytes_removed += size;
			read_map->erase(it);
			if (bytes_removed == bytes_read)
				break;
		}
		else 
		{
			std::pair <uint16_t, read_mapping> read_map_entry;
			

			struct read_mapping mapping;
			mapping.size = it->second.size - (bytes_read - bytes_removed);
			mapping.ack_num = it->second.ack_num;
			read_map_entry.first = (it->first + (bytes_read - bytes_removed)) % BUFFER_SIZE;
			read_map_entry.second = mapping;
			read_map->erase(it);
			read_map->insert(read_map_entry);
			break;
		}

		buf_index += size; 
		buf_index %= BUFFER_SIZE;
	}
}


uint16_t TCPAssignment::calculate_buffer_bytes (std::map<uint16_t, read_mapping> *read_map)
{
	uint16_t bytes_contains = 0;
	std::map<uint16_t, read_mapping>::iterator it;
	for (it = read_map->begin(); it != read_map->end(); ++it)
	{
		bytes_contains += it->second.size;
	}
	return bytes_contains;
}

uint32_t TCPAssignment::calculate_ack_num (struct socket_params *socket)
{
	std::map<uint16_t, read_mapping>::iterator it;
	std::map<uint16_t, read_mapping> *read_map = &socket->read_map;
	uint16_t last_byte_read = socket->last_byte_read;
	uint16_t buf_index = last_byte_read;

	uint32_t ack_num = socket->smallest_valid_seq_num;
	bool started = false;
	while (true)
	{
		it = read_map->find(buf_index);
		if (it == read_map->end() || (it->first == last_byte_read && started)) //not found
			return htonl(ack_num);

		started = true;
		ack_num = it->second.ack_num;
		buf_index += it->second.size;
		buf_index %= BUFFER_SIZE;
	}
}

uint16_t TCPAssignment::new_buf_index (struct socket_params *socket)
{
	std::map<uint32_t, write_mapping>::iterator it;
	std::map<uint32_t, write_mapping> *write_map = &socket->write_map;
	uint16_t buf_index = 0;

	for (it = write_map->begin(); it != write_map->end(); ++it)
	{
		buf_index = (it->second.buf_index + it->second.size) % BUFFER_SIZE;
	}
	return buf_index;
}

void TCPAssignment::clean_map (struct socket_params *socket)
{
	std::map<uint32_t, write_mapping>::iterator it;
	std::map<uint32_t, write_mapping> *write_map = &socket->write_map;

	for (it = write_map->begin(); it != write_map->end();)
	{
		if (it->first > socket->last_ack_received)
			break;

		it = write_map->erase(it);
	}
}

void TCPAssignment::unsend (struct socket_params *socket)
{
	std::map<uint32_t, write_mapping>::iterator it;
	std::map<uint32_t, write_mapping> *write_map = &socket->write_map;

	for (it = write_map->begin(); it != write_map->end(); ++it)
	{
		it->second.sent = false;
	}
}

uint16_t TCPAssignment::calculate_empty_space(struct socket_params *socket)
{
	std::map<uint32_t, write_mapping>::iterator it;
	std::map<uint32_t, write_mapping> *write_map = &socket->write_map;
	uint16_t empty_space = BUFFER_SIZE;

	for (it = write_map->begin(); it != write_map->end(); ++it)
	{
		empty_space -= it->second.size;
	}
	return empty_space;
}

void TCPAssignment::sendall (struct socket_params *socket)
{
	std::map<uint32_t, write_mapping>::iterator it;
	std::map<uint32_t, write_mapping> *write_map = &socket->write_map;

	uint8_t buffer[20];
	memset(buffer, 0, 20);

	uint32_t net_src_addr = htonl(socket->src_addr);
	uint32_t net_dest_addr = htonl(socket->dest_addr);
	uint16_t net_src_port = htons(socket->src_port);
	uint16_t net_dest_port = htons(socket->dest_port);
	uint32_t ack_num = htonl(socket->ack_num);
	uint16_t flags = htons(0x5010);
	uint16_t window = htons(BUFFER_SIZE - socket->read_window);
	
	memcpy(buffer + 2, &net_dest_port, 2);
	memcpy(buffer, &net_src_port, 2);
	memcpy(buffer + 8, &ack_num, 4);
	memcpy(buffer + 12, &flags, 2);
	memcpy(buffer + 12 + 2, &window, 2);


	uint16_t peer_window = socket->peer_window;
	for (it = write_map->begin(); it != write_map->end(); ++it)
	{
		if (it->second.sent)
			peer_window -= it->second.size;
	}



	for (it = write_map->begin(); it != write_map->end(); ++it)
	{
		struct write_mapping *mapping =	&it->second;

		if (mapping->size > peer_window)
			break;

		if (mapping->sent)
			continue;

		uint16_t bytes_to_send = mapping->size;

		uint8_t data_buffer[20 + bytes_to_send];

		uint16_t buf_tail = BUFFER_SIZE - mapping->buf_index;
		
		memcpy(data_buffer + 20, socket->write_buf + mapping->buf_index, buf_tail > bytes_to_send ? bytes_to_send : buf_tail);
		if (buf_tail < bytes_to_send)
			memcpy(data_buffer + 20 + buf_tail, socket->write_buf, bytes_to_send - buf_tail);


		Packet *packet = this->allocatePacket(54 + bytes_to_send);
		packet->writeData(14 + 4*3, &net_src_addr, 4);
		packet->writeData(14 + 4*4, &net_dest_addr, 4);
		
		memcpy(data_buffer, buffer, 20);
		uint32_t seq_num = htonl(mapping->seq_num);
		memcpy(data_buffer + 4, &seq_num, 4);

		uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_src_addr, net_dest_addr, data_buffer, 20 + bytes_to_send));							
		memcpy(data_buffer + 16, &checksum, 2);
		packet->writeData(14 + 20, data_buffer, 20 + bytes_to_send);
		this->sendPacket("IPv4", packet);

		mapping->sent = true;
		peer_window -= mapping->size;
	}

	if (!socket->timer_set && peer_window < socket->peer_window)
	{
		char *key = (char *) malloc(1 + sizeof(std::pair <int, int>));
		memset(key, 4, 1);
		memcpy(key + 1, &it->first, sizeof(std::pair <int, int>));
		socket->timer = addTimer((void *) key, TIMEOUT);
		socket->timer_set = true;
		socket->payload = key;
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	uint8_t *type = (uint8_t *) payload;
	if (*type == 1)
	{
		char *key_ptr = (char *) payload;
		std::pair <int, int> *key = (std::pair <int, int> *) (key_ptr + 1);
		socket_bindings.erase(*key);
		removeFileDescriptor(key->first, key->second);
	}
	else if (*type == 0)//waiting connection
	{
		char *key_ptr = (char *) payload;
		std::pair <int, int> *key = (std::pair <int, int> *) (key_ptr + 5);
		std::map<std::pair<int, int>, struct socket_params>::iterator it;
		it = socket_bindings.find(*key);
		
		uint32_t *num = (uint32_t *) (key_ptr + 1);
		struct listening_params *listen_struct = (it->second).listen_struct;
		struct waiting_connection *waiting_connection = listen_struct->waiting_list + *num;

		memset(waiting_connection, 0, sizeof(struct waiting_connection));
		listen_struct->waiting_count--;
		if (listen_struct->waiting_count == 0)
		{
			free(listen_struct->waiting_list);
			free(listen_struct->pending_list);
			free(listen_struct);
			removeFileDescriptor((it->first).first, (it->first).second);
			socket_bindings.erase(it->first);
			// return;
		}
	}
	else if (*type == 2) // connect
	{
		char *key_ptr = (char *) payload;
		std::pair <int, int> *key = (std::pair <int, int> *) (key_ptr + 1);
		std::map<std::pair<int, int>, struct socket_params>::iterator it;
		it = socket_bindings.find(*key);

		struct socket_params *socket = &it->second;

		Packet *packet = this->allocatePacket(14 + 20 + 20);
		uint8_t buffer[20];
		memset(buffer, 0, 20);

		uint32_t net_src_addr = htonl(socket->src_addr);
		packet->writeData(14 + 4*3, &net_src_addr, 4);

		uint32_t net_dest_addr = htonl(socket->dest_addr);
		packet->writeData(14 + 4*4, &net_dest_addr, 4); 

		uint16_t net_src_port = htons(socket->src_port);
		memcpy(buffer, &net_src_port, 2);

		uint16_t net_dest_port = htons(socket->dest_port);
		memcpy(buffer + 2, &net_dest_port, 2);

		uint32_t seq_num = htonl(SEQ_NUM);
		memcpy(buffer + 4, &seq_num, 4);

		uint16_t flags = htons(0x5002);
		memcpy(buffer + 12, &flags, 2);

		uint16_t window = htons(0xc800);
		memcpy(buffer + 12 + 2, &window, 2);

		uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_src_addr, net_dest_addr, buffer, 20));							
		memcpy(buffer + 16, &checksum, 2);

		socket->timer = addTimer(payload, TIMEOUT);

		packet->writeData(14 + 20, buffer, 20);
		this->sendPacket("IPv4", packet);
		return;
	}
	else if (*type == 3)
	{
		char *key_ptr = (char *) payload;
		std::pair <int, int> *key = (std::pair <int, int> *) (key_ptr + 5);
		std::map<std::pair<int, int>, struct socket_params>::iterator it;
		it = socket_bindings.find(*key);
		struct socket_params *socket = &it->second;
		
		uint32_t *num = (uint32_t *) (key_ptr + 1);
		struct listening_params *listen_struct = (it->second).listen_struct;
		struct pending_connection *pending_connection = listen_struct->pending_list + *num;

		Packet *response = this->allocatePacket(14 + 20 + 20);

		uint32_t net_receiver_addr = htonl(pending_connection->src_addr);
		response->writeData(14 + 4*3, &net_receiver_addr, 4);

		uint32_t net_sender_addr = htonl(pending_connection->dest_addr);
		response->writeData(14 + 4*4, &net_sender_addr, 4);

		uint8_t tcp_header_buffer[20];
		memset(tcp_header_buffer, 0, 20);

		uint16_t net_receiver_port = htons(socket->src_port);
		memcpy(tcp_header_buffer, &net_receiver_port, 2);

		uint16_t net_sender_port = htons(pending_connection->dest_port);
		memcpy(tcp_header_buffer + 2, &net_sender_port, 2);
		
		uint32_t seq_num = htonl(SEQ_NUM);
		memcpy(tcp_header_buffer + 4, &seq_num, 4);

		uint32_t ack_num = htonl(pending_connection->ack_num);
		memcpy(tcp_header_buffer + 8, &ack_num, 4);

		uint16_t new_flags = htons(0x5012);
		memcpy(tcp_header_buffer + 12, &new_flags, 2);
		
		uint16_t window = htons(0xc800);
		memcpy(tcp_header_buffer + 12 + 2, &window, 2);

		uint16_t checksum = htons(~NetworkUtil::tcp_sum(net_receiver_addr, net_sender_addr, tcp_header_buffer, 20));							
		memcpy(tcp_header_buffer + 16, &checksum, 2);

		response->writeData(14 + 20, tcp_header_buffer, 20);

		pending_connection->timer = addTimer(payload, TIMEOUT);

		this->sendPacket("IPv4", response);
		return;
	}
	else if (*type == 4)
	{
		char *key_ptr = (char *) payload;
		std::pair <int, int> *key = (std::pair <int, int> *) (key_ptr + 1);
		std::map<std::pair<int, int>, struct socket_params>::iterator it;
		it = socket_bindings.find(*key);
		struct socket_params *socket = &it->second;

		unsend(socket);
		sendall(socket);
		return;
	}

	free(payload);
	return;
}


}