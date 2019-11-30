# machsniff

*A prototype for sniffing mach RPCs*

## Objective

Proposes a method for tracing mach IPC messages to aid reverse engineering.  Mach services are fundamental primitives in OS X, used by many applications and background services to do non-trivial things.  Also, reverse engineering is fun.

## Background

* [Mach Overview](https://developer.apple.com/librarY/mac/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html): High level description of mach.
* [Mach RPC](https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/KernelProgramming/boundaries/boundaries.html#//apple_ref/doc/uid/TP30000905-CH217-BABDECEG): Description of mach rpc definitions.
* [Inter Process Communication](http://www.gnu.org/software/hurd/gnumach-doc/Inter-Process-Communication.html#Inter-Process-Communication):  Details of the mach RPC system
* [Wireshark](https://www.wireshark.org/): A network protocol analyzer, similar to tpcdump.
* [RPCSniffer](https://github.com/AdiKo/RPCSniffer): Sniffs WINDOWS RPC messages in a given RPC server process.
* [Overriding library functions in Mac OS X, the easy way](http://tlrobinson.net/blog/2007/12/overriding-library-functions-in-mac-os-x-the-easy-way-dyld_insert_libraries/): Describes how to intercept library calls using DYLD_INSERT_LIBRARIES.

## Detailed Design

Using [DYLD_INSERT_LIBRARIES](http://tlrobinson.net/blog/2007/12/overriding-library-functions-in-mac-os-x-the-easy-way-dyld_insert_libraries/), we can override library functions and intercept their arguments.  The basic premise is to write some code that intercepts the system call, logs some data, then hands off to the original call resuming the program uninterrupted.  The overrides happen without modifying the original program by simply setting environment variables.  The original function address can be looked up using [dlsym](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man3/dlsym.3.html).

## Intercepting RPC calls
The lifetime of a mach rpc call can be broken down into the following steps:
Figure out the port that you want to talk to using bootstrap_look_up ([bootstrap.h](http://www.opensource.apple.com/source/launchd/launchd-328/launchd/src/bootstrap.h))
Send and receive messages on the ports using mach_msg ([mach_msg](http://web.mit.edu/darwin/src/modules/xnu/osfmk/man/mach_msg.html))

We can write some stub code with the same definitions as the original calls, looks up the original symbol, and invokes it.  The stub can record the arguments such as the mach header and the original message contents, port numbers, etc.  Further, we can keep track of the port returned by bootstrap_look_up, then associate mach_msg calls with the original service name.

## Viewing the Results

A similar tool for windows called [RPCSniffer](https://github.com/AdiKo/RPCSniffer) uses [Pipes](https://wiki.wireshark.org/CaptureSetup/Pipes) with a custom wireshark dissector to view the results.  However, the main drawback of using pipes is that you need to synchronize capture and reading, otherwise data is lost.  That is, the sniffer can start writing to the pipe before wireshark is reading from it.  We’ll take a similar approach of using a packet capture app like wireshark or tcpdump, but instead just write to files using the [Libpcap File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat).  Since both approaches use the same format, machsniff could be changed to also use pipes easily in the future.

### Pyreshark

We need a custom Wireshark dissector plugin in order to view the contents of the messages.
Wireshark dissectors plugins typically are compiled into the binary.  pyreshark lets you write custom python dissectors, but you just have to compile pyreshark into wireshark.

There may be some packaged wireshark + pyreshark distributions out there, but there does not appear to be one for OS X at this time.  We’ll clone the wireshark git repot with a patch of pyreshark built into it for our own use, and it may save some time for others in the future.

