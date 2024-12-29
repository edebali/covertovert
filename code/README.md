# Covert Storage Channel That Exploits Protocol Field Manipulation Using Precision Field in NTP

This project investigates a covert storage channel that exploits protocol field manipulation using the precision field in the Network Time Protocol (NTP). The goal is to show how common fields in popular protocols can be used to secretly send data out.

## Members and Group Information

This project is the second phase of Data Communications and Networking course at Middle East Technical University Department of Computer Engineering (CENG 435), and we are in Group 48.

* Mehmet Edebali Şener
* Berhem Şervan Gök

One can find the source code at https://github.com/edebali/covertovert.

## Background

Network Time Protocol (NTP) is a networking protocol for clock synchronization between computer systems. The precision field in NTP indicates the precision of the system clock. This project explores how this field can be manipulated to encode and transmit hidden information.

## Methodology

1. **Protocol Analysis**: We analyzed the NTP protocol to identify fields that can be manipulated without disrupting the primary function of time synchronization.
2. **Field Manipulation**: We focused on the precision field, modifying its value to encode data.
3. **Data Encoding**: We developed an encoding scheme to represent binary data using the precision field.
4. **Transmission and Reception**: We implemented a system to send and receive covert messages using the modified NTP packets.

## Implementation

### Encoding

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


### Decoding

**Precision Field Analysis**:
* The precision field of each packet is extracted.
* Using the same payload-based properties (total and average), the precision field is decoded back into bits.

**Bit Reassembly**:
* The decoded bits are concatenated into a binary sequence.
* Once 8 bits are collected, they are converted into a character.
* The process continues until the stop character (.) is detected, signaling the end of the message.

### Configuration

One can find configuration parameters in config.json.
Some of the parameters and their meanings are provided just below.

- debug: If true, prints additional information about sent & received bits and NTP precision values.

#### Sender parameters
- log_file_name: Sender log filename
- destination_ip: Destination IP address, i.e., receiver's IP address
- ntp_port: Destination port number.
- min_length_bytes: Minimum number of bytes to be sent.
- max_length_bytes: Minimum number of bytes to be sent. If min and max bytes are the same, exactly that number of bytes will be sent. If not, data length will be randomly set between min and max.

#### Receiver parameters
- log_file_name: Receiver log filename
- timeout: Timeout in seconds that is passed to sniff method.
- source_ip: Sender's IP address
- ntp_port: Destination port number that is provided to the sniff method.

### Covert Channel Capacity

Capacity of this covert channel implementation is calculated by sending 128-bit message and measuring the time difference between just after sending the last packet and just before sending the first packet, and then dividing 128 by that time difference (in seconds).
We measured time difference ten times and take their average to give a better estimate of capacity.

Measurements:
1.  2.486064072 seconds
2.  2.431879379 seconds
3.  2.179883344 seconds
4.  1.871852196 seconds
5.  1.890032707 seconds
6.  1.939514572 seconds
7.  2.008998501 seconds
8.  1.788839719 seconds
9.  2.394864751 seconds
10. 2.438875311 seconds

- Average: 2.1430804552 seconds
- Capacity = 128 / Average = 59.727109

## Key Advantages of the Approach

**Dynamic and Obfuscated**:
* Encoding depends on the payload, making detection and reverse engineering difficult.

**Protocol Compliance**:
* The precision field is a legitimate part of the NTP protocol, avoiding obvious anomalies.

**Efficient Communication**:
* By encoding 1-2 bits per packet, the channel balances capacity and stealth.

In summary, MyCovertChannel.py cleverly uses the NTP protocol's precision field and payload properties to establish a covert, undetectable communication channel. The encoding and decoding processes are tightly coupled, ensuring reliable message transfer while maintaining secrecy.
