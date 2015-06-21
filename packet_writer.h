#ifndef __PACKET_WRITER_H__
#define __PACKET_WRITER_H__

#include <sys/types.h>
#include <mach/mach.h>

// Library for writing captured mach rpc packets.
//
// Currently, this ends up writing a pcap file to disk, but this could be
// changed in the future to write to a pipe or some other file format.

// Appens the specified packet to the dump file.  packet_len refers to the size
// of the memory pointed to by packet.  actual_len refers to the actual size on
// the wire, which may be different from packet_len if the packet is truncated.
void write_packet(const mach_msg_header_t* packet, size_t packet_len);

#endif  // __PACKET_WRIRTER_H__
