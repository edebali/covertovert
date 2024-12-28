from CovertChannelBase import CovertChannelBase
from scapy.all import *
from scapy.layers.ntp import NTP
from scapy.layers.inet import IP
from scapy.layers.inet import UDP
import json

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()
        self.ntp_port = 123
        with open('config.json', 'r') as f:
            self.debug = json.load(f).get('debug', False)

    def debug_print(self, message):
        """
        Print message only if debug is enabled.
        """
        if self.debug:
            print(message)

    def calculate_payload_factor(self, payload):
        """
        Calculate a binary factor based on payload characteristics.
        Returns 0 or 1 to adjust the precision value.
        """
        payload_bytes = payload.encode('utf-8')

        factors = [
            len(payload) % 2,
            sum(1 for c in payload if c.isupper()) % 2,
            sum(1 for c in payload if c.isdigit()) % 2,
            (sum(b for b in payload_bytes) % 2)
        ]
        
        return sum(factors) % 2

    def create_ntp_packet(self, precision_value, payload):
        """
        Create NTP packet with specified precision value and payload.
        """
        return IP(dst="172.18.0.3")/UDP(sport=RandShort(), dport=self.ntp_port)/NTP(precision=precision_value)/Raw(load=payload)

    def encode_bit(self, bit, payload):
        """
        Encode a single bit using precision value and payload factor.
        Uses standard NTP precision values -6 and -7.
        """
        payload_factor = self.calculate_payload_factor(payload)
        should_use_higher = int(bit) ^ payload_factor

        return -6 if should_use_higher else -7

    def decode_bit(self, precision_value, payload):
        """
        Decode precision value back to bit using payload factor.
        """
        payload_factor = self.calculate_payload_factor(payload)

        received_higher = 1 if precision_value == -6 else 0
        return str(received_higher ^ payload_factor)

    def send(self, log_file_name, delay_ms):
        """
        Send covert message using NTP precision field.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        self.debug_print(f"Starting to send message of length: {len(binary_message)} bits")

        for i, bit in enumerate(binary_message):
            try:
                payload = self.generate_random_message()
                precision = self.encode_bit(bit, payload)
                packet = self.create_ntp_packet(precision, payload)
                CovertChannelBase.send(self, packet)
                
                self.debug_print(f"Sent bit {bit} with precision {precision}, payload factor {self.calculate_payload_factor(payload)}")

                self.sleep_random_time_ms(1, 2)
                
            except Exception as e:
                self.debug_print(f"Error sending bit {i}: {e}")

    def receive(self, timeout, log_file_name):
        """
        Receive and decode covert message.
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
                    
                    bit = self.decode_bit(precision, payload)
                    received_bits += bit
                    
                    self.debug_print(f"Received precision {precision}, decoded bit {bit}, payload factor {self.calculate_payload_factor(payload)}")
                    
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
            sniff(filter=f"udp and port {self.ntp_port}", 
                  prn=process_packet,
                  stop_filter=lambda _: stop_sniffing,
                  timeout=timeout)
            
            self.debug_print(f"Final received message: {received_message}")
            self.log_message(received_message, log_file_name)
            
        except Exception as e:
            self.debug_print(f"Error in receiver: {e}")
            if received_message:
                self.log_message(received_message, log_file_name)
