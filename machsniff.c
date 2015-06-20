// Proof of concept for sniffing mach messages using a dynamic library
// override.
// $ make
// $ MACHSNIFF_OUTPUT="mach.pcap" DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=machsniff.dylib <command>
//
// TODO(allen): Remove debugging output, and put all interesting information from
// the mach header into the pcap file.

#include <stdio.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

#include "packet_writer.h"

static mach_msg_return_t (*orig_mach_msg)(mach_msg_header_t* msg,
    mach_msg_option_t option, mach_msg_size_t send_size,
    mach_msg_size_t rcv_size, mach_port_t rcv_name, mach_msg_timeout_t timeout,
    mach_port_t notify) = NULL;

static kern_return_t (*orig_bootstrap_look_up)(mach_port_t bp,
    const name_t service_name, mach_port_t *sp) = NULL;

static kern_return_t (*orig_bootstrap_look_up2)(mach_port_t bp,
    const name_t service_name, mach_port_t *sp, pid_t target_pid,
    uint64_t flags) = NULL;

mach_msg_return_t mach_msg(mach_msg_header_t* msg, mach_msg_option_t option,
    mach_msg_size_t send_size, mach_msg_size_t rcv_size,
    mach_port_t rcv_name, mach_msg_timeout_t timeout, mach_port_t notify) {
  if (orig_mach_msg == NULL) {
    orig_mach_msg = dlsym(RTLD_NEXT, "mach_msg");
    printf("mach_host_self() = %d\n", mach_host_self());
    printf("mach_task_self() = %d\n", mach_task_self());
    printf("mig_get_reply_port() = %d\n", mig_get_reply_port());
  }
  if (option & MACH_SEND_MSG) {
    printf("==> mach_msg(id=%d)(rcv_name=%d)(remote_port=%d)(local_port=%d)\n",
        msg->msgh_id, rcv_name, msg->msgh_remote_port, msg->msgh_local_port);
    if (send_size > 0) {
      unsigned char * buf = (unsigned char*)(msg + 1);
      write_packet(buf, send_size, send_size);    
    }
  } else if (option & MACH_RCV_MSG)  {
    printf("<== mach_msg(%d)(%d)\n", rcv_name, msg->msgh_remote_port);
  }
  return orig_mach_msg(msg, option, send_size, rcv_size, rcv_name, timeout,
      notify);
}

kern_return_t bootstrap_look_up(mach_port_t bp, const name_t service_name,
    mach_port_t *sp) {
  if (orig_bootstrap_look_up == NULL) {
    orig_bootstrap_look_up = dlsym(RTLD_NEXT, "bootstrap_look_up");
  }
  kern_return_t ret = orig_bootstrap_look_up(bp, service_name, sp);
  printf("bootstrap_look_up(%s) = %d, %d\n", service_name, ret, *sp);
  return ret;
}

kern_return_t bootstrap_look_up2(mach_port_t bp, const name_t service_name,
    mach_port_t *sp, pid_t target_pid, uint64_t flags) {
  if (orig_bootstrap_look_up2 == NULL) {
    orig_bootstrap_look_up2 = dlsym(RTLD_NEXT, "bootstrap_look_up2");
  }
  kern_return_t ret = orig_bootstrap_look_up2(bp, service_name, sp, target_pid,
      flags);
  printf("bootstrap_look_up2(%s) = %d, %d\n", service_name, ret, *sp);
  return ret;
}

