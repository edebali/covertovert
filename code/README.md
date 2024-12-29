# Covert Storage Channel That Exploits Protocol Field Manipulation Using Precision Field in NTP

This project investigates a covert storage channel that exploits protocol field manipulation using the precision field in the Network Time Protocol (NTP). The goal is to show how common fields in popular protocols can be used to secretly send data out.

## Background

Network Time Protocol (NTP) is a networking protocol for clock synchronization between computer systems. The precision field in NTP indicates the precision of the system clock. This project explores how this field can be manipulated to encode and transmit hidden information.

## Methodology

1. **Protocol Analysis**: We analyzed the NTP protocol to identify fields that can be manipulated without disrupting the primary function of time synchronization.
2. **Field Manipulation**: We focused on the precision field, modifying its value to encode data.
3. **Data Encoding**: We developed an encoding scheme to represent binary data using the precision field.
4. **Transmission and Reception**: We implemented a system to send and receive covert messages using the modified NTP packets.

## Implementation

# Encoding

**Payload Analysis**:
* The payload (randomly generated content) is analyzed to derive properties such as total (even/odd) and average (computed characteristic based on ASCII values of the payload).
* These properties dynamically determine how the encoding operates, making it harder for outsiders to predict the pattern.

**Precision Field Mapping**:
* Bits from the binary message are encoded into the precision field.
* For example:
If total is even, up to 2 bits can be encoded in precision value.
If total is odd, only 1 bit is encoded with different mapping rules.
* This dynamic approach ensures the encoding adapts based on the payload, adding a layer of obfuscation.

**Packet Creation**:
* Each encoded precision value is embedded into an NTP packet along with the payload.
* The packets are sent with random delays to mimic legitimate network traffic.


# Decoding

**Precision Field Analysis**:
* The precision field of each packet is extracted.
* Using the same payload-based properties (total and average), the precision field is decoded back into bits.

**Bit Reassembly**:
* The decoded bits are concatenated into a binary sequence.
* Once 8 bits are collected, they are converted into a character.
* The process continues until the stop character (.) is detected, signaling the end of the message.


# Key Advantages of the Approach

**Dynamic and Obfuscated**: Encoding depends on the payload, making detection and reverse engineering difficult.
**Protocol Compliance**: The precision field is a legitimate part of the NTP protocol, avoiding obvious anomalies.
**Efficient Communication**: By encoding 1-2 bits per packet, the channel balances capacity and stealth.

In summary, MyCovertChannel.py cleverly uses the NTP protocol's precision field and payload properties to establish a covert, undetectable communication channel. The encoding and decoding processes are tightly coupled, ensuring reliable message transfer while maintaining secrecy.
