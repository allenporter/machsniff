# A pyreshark dissector for the mach RPC system.
#
# This is based on the RPCSniffer rpc protocol dissector for windows
# found at https://github.com/AdiKo/RPCSniffer/ which is accomplishing
# something similar for windows IPC.
#
# See https://github.com/ashdnazg/pyreshark/wiki/Writing-Dissectors for
# information about writing pyreshark dissectors.
#
# See http://www.gnu.org/software/hurd/gnumach-doc/Message-Format.html for
# details about the mach message format.

from cal.cal_types import ProtocolBase
from cal.cal_types import FieldItem
from cal.cal_types import PyFunctionItem
from cal.cal_types import Subtree
from cal.cal_types import TextItem
from cal.ws_consts import FT_UINT32
from cal.ws_consts import BASE_HEX

# First ID in the private reserved range
ETHERNET_TYPE = 147

MSGH_BIT_STRINGS = {
  0x0000001fL: "MACH_MSGH_BITS_REMOTE_MASK",
  0x00001f00L: "MACH_MSGH_BITS_LOCAL_MASK",
  0x80000000L: "MACH_MSGH_BITS_COMPLEX",
}

class Protocol(ProtocolBase):
  def __init__(self):
    self._name = "Mach RPC Message"
    self._filter_name = "machrpc"
    self._short_name = "MachRPC"
    self._items = [
      # Is one than one bit ever set at once? If so this likely won't work
      FieldItem("msgh_bits", FT_UINT32, "Message Bits", strings = MSGH_BIT_STRINGS),
      FieldItem("msgh_size", FT_UINT32, "Message Size", display = BASE_HEX),
      FieldItem("remote_port", FT_UINT32, "Remote Port", display = BASE_HEX),
      FieldItem("local_port", FT_UINT32, "Local Port", display = BASE_HEX),
      FieldItem("msgh_seqno", FT_UINT32, "Sequence Number", display = BASE_HEX),
      FieldItem("msgh_id", FT_UINT32, "Message ID", display = BASE_HEX),
    ]
    # The items above should consume the entire mach_msg_header_t leaving
    # packet.offset pointed at raw data which can be interpereted by the
    # next dissector which is "data"
