# Done per connection
# Each connection has the information about recv/
PACKETS = {}

def tcp_reassemble(fn):
    def _inner(_pkt):
        global PACKETS

        conn_key = "%d-%d" % (_pkt['TCP'].sport, _pkt['TCP'].dport)

        # This function returns True if we don't want to delete the packet that we're looking at.
        def look_at_packet(pkt):
            if conn_key not in PACKETS:
                PACKETS[conn_key] = {
                    "next_sequence": 0,
                    "packets": {},
                }
            
            if pkt['TCP'].flags & 2 == 2:
                PACKETS[conn_key]["next_sequence"] = pkt.seq + 1        # Next sequence is always +1 from this one.
                return False

            if hasattr(pkt, "load"):
                data = bytes(pkt['TCP'].load)
                length = len(data)
                if length == 0 or pkt['TCP'].payload.name == "Padding":
                    return False
                
                next_seq = PACKETS[conn_key]["next_sequence"]
                if next_seq == 0:
                    # Not yet initialized.
                    return

                # Sequence analysis (example packet ordering below):
                #
                #   |===|         |======|
                #      |=========|
                #   |===============|
                #           |===|
                #
                if pkt.seq == next_seq:
                    # Normal next sequence, continue on!
                    pass
                elif pkt.seq + length <= next_seq:
                    # Spurrious retransmission, ignore.
                    return False
                elif pkt.seq > next_seq:
                    # Future packet for which we have not yet looked at the data.
                    if pkt.seq not in PACKETS[conn_key]["packets"]:
                        PACKETS[conn_key]["packets"][pkt.seq] = pkt
                    return True
                elif pkt.seq < next_seq:
                    # We have an old packet with new data, so we'll process it.
                    offset = next_seq - pkt.seq
                    data = data[offset:]
                    length -= offset
                else:
                    print("Packet situation is weird and unexpected!")

                # data and length should be the correct stuff from here.
                fn(data, pkt)

                # The next sequence is whatever we just parsed in terms of length.
                PACKETS[conn_key]["next_sequence"] += length
                return False
        
        look_at_packet(_pkt)
        if len(PACKETS[conn_key]["packets"]) > 0:
            to_delete = []

            # Loop through the future packets and see if we need to reprocess.
            for k in PACKETS[conn_key]["packets"].keys():
                delay = look_at_packet(PACKETS[conn_key]["packets"][k])
                if not delay:
                    to_delete.append(k)
            
            # Now delete ones we don't need
            for k in to_delete:
                del PACKETS[conn_key]["packets"][k]
    
    return _inner