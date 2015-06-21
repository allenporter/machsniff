#include "packet_writer.h"

#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>

// A header type in the private reserved range
#define DLT_MACHSNIFF 147

static pcap_t* pd = NULL;
static pcap_dumper_t* pdumper = NULL;
static size_t max_packet_len = 0xff00;

// Cleans up initialization performed by init_writer.  Note that init_writer only
// registers this handler if the pcap handle is actually initialized.
static void cleanup_handler(int signum) {
  if (pd == NULL) {
    return;
  }
  pcap_dump_close(pdumper);
  pdumper = NULL;
  pcap_close(pd);
  pd = NULL;
  exit(signum);
}

// Register cleanup handlers that flush/close the pcap file.
static void register_cleanup_handler() {
  if (signal(SIGINT, cleanup_handler) == SIG_IGN) {
    signal(SIGINT, SIG_IGN);
  }
  if (signal(SIGTERM, cleanup_handler) == SIG_IGN) {
    signal(SIGTERM, SIG_IGN);
  }
  if (signal(SIGKILL, cleanup_handler) == SIG_IGN) {
    signal(SIGKILL, SIG_IGN);
  }
}

// Initializes the packet writer.  Opens a pcap file handle, and registers cleanup.
static void init_writer() {
  if (pd != NULL) {
    // Only initialize once.
    // TODO(allen): Perhaps we should be worried about multi-threaded code here.
    // Instead, use pthread_once or something similar to initialize this once and
    // lock all file access with a mutex.
    return;
  }
  char* output_filename = getenv("MACHSNIFF_OUTPUT");
  if (output_filename == NULL) {
    // Machsniff capture disabled
    return;
  }
  pd = pcap_open_dead(DLT_MACHSNIFF, max_packet_len /* snaplen */);
  if (pd == NULL) {
    fprintf(stderr, "pcap_open_dead failed\n");
    exit(1);
  }
  pdumper = pcap_dump_open(pd, output_filename);
  if (pdumper == NULL) {
    fprintf(stderr, "pcap_dump_open failed: %s\n", pcap_geterr(pd));
    exit(1);
  }
  register_cleanup_handler();
}

void write_packet(const mach_msg_header_t* packet, size_t packet_len) {
  init_writer();

  struct pcap_pkthdr header;
  gettimeofday(&header.ts, NULL);
  header.caplen = packet_len;
  header.len = packet_len;
  pcap_dump((u_char *)pdumper, &header, (const u_char*)packet);
}
