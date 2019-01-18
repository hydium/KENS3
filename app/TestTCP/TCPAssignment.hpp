/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{

struct read_mapping 
{
	uint16_t size; // size of the segment
	uint32_t ack_num;
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	void syscall_socket(UUID syscallUUID, int pid);
	void syscall_close(UUID syscallUUID, int pid, int fd);
	void syscall_read(UUID syscallUUID, int pid, int fd, char *given_buf, int count);
	void syscall_write(UUID syscallUUID, int pid, int fd, char *given_buf, int count);
	void syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr_in *addr, socklen_t len);
	void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
	void syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr_in* addr, socklen_t *len);
	void syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr_in * addr, socklen_t len);
	void syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr_in *addr, socklen_t *len);
	void syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr_in *addr, socklen_t *len);
	
	uint16_t calculate_read_window(std::map<uint16_t, read_mapping> *read_map, uint16_t buf_index);
	uint16_t calculate_buffer_bytes (std::map<uint16_t, read_mapping> *read_map);
	uint32_t calculate_ack_num (struct socket_params *socket);
	void reflect_read(struct socket_params *socket, uint16_t bytes_read);

	void sendall (struct socket_params *socket);
	uint16_t calculate_empty_space(struct socket_params *socket);
	void unsend (struct socket_params *socket);
	void clean_map (struct socket_params *socket);
	uint16_t new_buf_index (struct socket_params *socket);
private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
