from scapy.all import *
from collections import defaultdict, deque

# Setting default value of flow_stats in case of missing value, by using defaultdict
'''
 From kahraman kostas, 8 features with highest feature importance are:
 Result: 
 Bwd Packet Length Std
 Flow Byte/s
 Total Length of Fwd Packets 
 Fwd Packet Length Std
 Flow IAT Std
 Flow IAT Min
 Fwd IAT Total
'''
flow_stats = defaultdict(lambda: {
            "start_time": None,
            "end_time": None,
            "fwd_packet_lengths": deque(maxlen=100),
            "bwd_packet_lengths": deque(maxlen=100),
            "flow_iats": deque(maxlen=100),
            "flow_byte/s":0,
            "last_packet_time": None,
            "fwd_packet_length_std": 0,
            "bwd_packet_length_std": 0,
            "fwd_packet_length_total": 0,
            "packet_length_total": 0,
            "flow_iat_min": 0,
            "flow_iat_std": 0,
            "flow_iat_total": 0,
        })

total_packet_processed = 0

# def feature_extractor(packet, flow):
#     flow['fwd_packet_length_std'] = 
#     flow['bwd_packet_length_std'] = 
#     flow['fwd_packet_length_total'] = 
#     flow['flow_iat_min'] = 
#     flow['flow_iat_std'] = 
#     flow['flow_iat_total'] = 
#     flow['flow_byte/s'] = 

def packet_parser(packet):
    if IP not in packet:
        return
    
    global total_packet_processed
    total_packet_processed += 1


    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        protocol = 'TCP'
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = 'UDP'
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        return
    
    # Generate flow identifier as 5-tuple network flow
    forward_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    backward_key = f"{dst_ip}:{dst_port}-{dst_ip}:{src_port}-{protocol}"

    # Get packer length, current time
    packet_length = len(packet)
    current_time = time.time()
    is_forward = True

    # Check if the packet is a new flow
    if forward_key in flow_stats:
        flow_key = forward_key
    elif backward_key in flow_stats:
        flow_key = backward_key
        is_forward = False
    else:
        flow_key = forward_key

    # Select flow on flow_states based on flow_key
    flow = flow_stats[flow_key]

    # Update start_time
    if flow['start_time'] is None:
        flow['start_time'] = current_time
    # Update end_time
    flow['end_time'] = current_time

    # Update fwd_packet_lengths
    if is_forward:
        flow['fwd_packet_lengths'].append(packet_length)
    # Update bwd_packet_lengths
    else:
        flow['bwd_packet_lengths'].append(packet_length)

    # Update flow_iats (inter arrival time)
    if flow['last_packet_time'] is not None:
        flow['flow_iats'].append(current_time - flow['last_packet_time'])

    # Update packet_length_total
    flow['packet_length_total'] += packet_length

    # Update last_packet_time
    flow['last_packet_time'] = current_time

    print(flow_stats)
    # feature_extractor(packet, flow)
def packet_capture():
    try:
        sniff(iface="en0", prn=packet_parser)
    except Exception as e:
        print(f"Capture error: {e}")

def main():
    packet_capture()

if __name__== "__main__":
    main()