-- A LUA dissector for output files written by packet_writer.{c,h}.  To make
-- this work in wireshark you need to first let wireshark find this script.
-- The simplest way is with the -X command line flag like this:
--   $ wireshark -X lua_script:/path/to/machsniff/machrpc-dissector.lua
-- Then, you need to tell wireshark to interpret packet writer dumps as
-- machrpc.  Wireshark > Preferences > Protocols > DLT_USER then Edit... the
-- encapsulations table.  You need to set the payload protocol for DLT
-- User 0 (DLT=147) to "machrpc".

local machrpc = Proto("machrpc", "MachRPC", "Mach RPC protocol")

MACH_MSGH_BITS_REMOTE_MASK = 0x0000001f
MACH_MSGH_BITS_LOCAL_MASK = 0x00001f00
MACH_MSGH_BITS_COMPLEX = 0x80000000

machrpc.fields = {}
local f = machrpc.fields
f.msgh_bits = ProtoField.uint32("machrpc.msgh_bits", "Message Bits")
f.msgh_size = ProtoField.uint32("machrpc.msgh_size", "Message Size")
f.remote_port = ProtoField.uint32("machrpc.remote_port", "Remote Port")
f.local_port = ProtoField.uint32("machrpc.local_port", "Local Port")
f.msgh_seqno = ProtoField.uint32("machrpc.msgh_seqno", "Sequence Number")
f.msgh_id = ProtoField.uint32("machrpc.msgh_id", "Message ID")

function machrpc.dissector(buf, pkt, root)
  local subtree = root:add(machrpc, buf(), "MachRpc ("..buf:len()..")")
  local offset = 0

  --- TODO(allen): Use MACH_MSGH_BITS_* masks above to print better details
  subtree:add_le(f.msgh_bits, buf(offset, 4))
  offset = offset + 4
  subtree:add_le(f.msgh_size, buf(offset, 4))
  offset = offset + 4
  subtree:add_le(f.remote_port, buf(offset, 4))
  offset = offset + 4
  subtree:add_le(f.local_port, buf(offset, 4))
  offset = offset + 4
  subtree:add_le(f.msgh_seqno, buf(offset, 4))
  offset = offset + 4
  subtree:add_le(f.msgh_id, buf(offset, 4))
  offset = offset + 4
end

function machrpc.init()
  local wtap_encap_table = DissectorTable.get("wtap_encap")
  wtap_encap_table:add(wtap.USER0, machrpc)
end
