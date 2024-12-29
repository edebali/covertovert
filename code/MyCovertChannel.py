from CovertChannelBase import CovertChannelBase
from scapy.all import *
from scapy.layers.ntp import NTP
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
import json

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()
        with open('config.json', 'r') as f:
            self.debug = json.load(f).get('debug', False)

    def debug_print(self, message):
        """
        Print message only if debug is enabled.
        """
        if self.debug:
            print(message)

    def calculate_payload_info(self, payload):
        """
        Calculate total and avg values from payload
        Returns (total, avg) where:
        - total is binary (0 or 1)
        - avg is between 0-3 or 0-1 depending on total
        """
        total = sum(ord(c) for c in payload)
        avg = (int(total / len(payload)) % (4 if total % 2 == 0 else 2)) if len(payload) > 0 else 0
        total = total % 2
        
        return total, avg

    def create_ntp_packet(self, precision_value, payload, destination_ip, ntp_port):
        """
        Create NTP packet with specified precision value, payload, and network parameters.
        """
        return IP(dst=destination_ip)/UDP(sport=RandShort(), dport=ntp_port)/NTP(precision=precision_value)/Raw(load=payload)

    def encode_bit(self, bits, payload):
        """
        Encode bits using precision value based on payload characteristics
        Uses range [-6, -11] corresponding to [0, 5]
        """
        total, avg = self.calculate_payload_info(payload)
        
        if total == 0:
            if len(bits) >= 2:
                bits_value = int(bits[:2], 2)
                result = bits_value ^ avg
                return -(result + 6), 2
            else:
                bit_value = int(bits[0])
                result = 4 if bit_value == 0 else 5
                return -(result + 6), 1 
        else: 
            bit_value = int(bits[0])
            result = bit_value ^ (avg % 2)
            return -(result + 6), 1 

    def decode_bit(self, precision_value, payload):
        """
        Decode precision value back to bits using payload characteristics
        """
        total, avg = self.calculate_payload_info(payload)
        
        value = abs(precision_value) - 6
        
        if total == 0:
            if value in [4, 5]:
                return str(value - 4), 1
            else:
                result = value ^ avg
                return format(result, '02b'), 2
        else:
            result = value ^ (avg % 2)
            return str(result), 1

    def send(self, log_file_name, destination_ip, ntp_port):
        """
        Send covert message using NTP precision field
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        self.debug_print(f"Starting to send message of length: {len(binary_message)} bits")
        
        remaining_bits = binary_message
        while remaining_bits:
            try:
                payload = self.generate_random_message()
                precision, bits_used = self.encode_bit(remaining_bits, payload)
                packet = self.create_ntp_packet(precision, payload, destination_ip, ntp_port)
                CovertChannelBase.send(self, packet)
                
                total, avg = self.calculate_payload_info(payload)
                self.debug_print(f"Sent {bits_used} bits ({remaining_bits[:bits_used]}) "
                            f"with precision {precision}, total={total}, avg={avg}")
                
                remaining_bits = remaining_bits[bits_used:]
                self.sleep_random_time_ms()
                
            except Exception as e:
                self.debug_print(f"Error sending: {e}")

    def receive(self, timeout, log_file_name, source_ip, ntp_port):
        """
        Receive and decode covert message
        """
        received_bits = ""
        received_message = ""
        stop_sniffing = False
        
        def process_packet(packet):
            nonlocal received_bits, received_message, stop_sniffing
            
            try:
                if NTP in packet and Raw in packet:
                    precision = packet[NTP].precision
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    bits, bits_decoded = self.decode_bit(precision, payload)
                    received_bits += bits
                    
                    total, avg = self.calculate_payload_info(payload)
                    self.debug_print(f"Received precision {precision}, decoded {bits_decoded} bits: {bits}, "
                                f"total={total}, avg={avg}")
                    
                    while len(received_bits) >= 8:
                        char = self.convert_eight_bits_to_character(received_bits[:8])
                        received_message += char
                        received_bits = received_bits[8:]
                        
                        self.debug_print(f"Decoded character: {char}")
                        
                        if char == '.':
                            stop_sniffing = True
                            return True
                                
            except Exception as e:
                self.debug_print(f"Error processing packet: {e}")
                return False

        try:
            self.debug_print("Starting packet capture...")
            sniff(filter=f"udp and port {ntp_port} and ip src {source_ip}",
                prn=process_packet,
                stop_filter=lambda _: stop_sniffing,
                timeout=timeout)
            
            self.debug_print(f"Final received message: {received_message}")
            self.log_message(received_message, log_file_name)
            
        except Exception as e:
            self.debug_print(f"Error in receiver: {e}")
            if received_message:
                self.log_message(received_message, log_file_name)
