from pwn import *


def print_data(byte):
    print('00AQchan 01nelxxx 10xxxxxx 11xxxxxx')
    print('--------:--------:--------:--------')
    for i in byte:
        print('{:08b}'.format(i), end=' ')
    print()


def decode_abort(byte):
    mesg = byte[3] & 0b00111111
    if mesg == 0:
        print('Abort: SYSTEM ABORTED')
    elif mesg == 1:
        print('Abort: INVALID SIGNATURE')
    elif mesg == 2:
        print('Abort: INVALID SIZE')
    elif mesg == 3:
        print('Abort: READ ONLY VALUE')
    elif mesg == 4:
        print('Abort: CLIENT TIMEOUT')
    elif mesg == 5:
        print('Abort: UNRESPONSIVE CLIENT')
    elif mesg == 6:
        print('Abort: UNKNOWN I/O CHANNEL')
    else:
        print('Abort: unknown abort code!!')


def decode_channel(channel):
    if channel == 0:
        print('TLE Data: ', end='')
    elif channel == 1:
        print('Name: ', end='')
    elif channel == 2:
        print('Mass: ', end='')
    elif channel == 3:
        print('Time: ', end='')
    elif 3 < channel < 8:
        print('Unused: ', end='')
    elif channel == 8:
        print('Velocity: ', end='')
    elif channel == 9:
        print('Altitude: ', end='')
    elif channel == 16:
        print('???: ', end='')
    elif channel == 64:
        print('Heartbeat: ', end='')
    elif channel == 65:
        print('Abort: ', end='')
    else:
        print('Unknown channel: ', end='')


def decode_message(byte):
    channel = ((byte[0] & 0b00001111) << 3) | ((byte[1] & 0b00111000) >> 3)
    decode_channel(channel)
    print("Value:", '{:03b} {:06b} {:06b}'.format(
        byte[1] & 0b111, byte[2] & 0b111111, byte[3] & 0b111111), end=' ')
    if byte[0] & 0b00100000:
        decode_abort(byte)
    else:
        print('Unknown response')
    print()


def get_data(byte):
    return ((byte[1] & 0b111) << 12) | ((byte[2] & 0b111111) << 6) | (byte[3] & 0b111111)


def group(data):
    group_count = len(data) // 8
    data = data[:group_count*8]
    ret = [int(data[8*i:8*i+8], 2) for i in range(group_count)]
    return ret


p = remote('uplink.ritsec.club', 8001)
packet_index = 0
record = ''
not_sent = True
while True:
    recv = p.recv(4)
    print_data(recv)
    print(packet_index, end=' ')
    decode_message(recv)

    if 0 < packet_index < 27:
        data = get_data(recv)
        record += '{:015b}'.format(data)

    if packet_index == 27:
        print(len(record))
        print(''.join(chr(c) for c in group(record)))
        break

    if not_sent:
        # Time, 26 responses
        # p.send(int.to_bytes(0b00010000_01011000_10000000_11000000, 4, 'big'))

        # Velocity, 26 responses
        # p.send(int.to_bytes(0b00010001_01000000_10000000_11000000, 4, 'big'))

        # Altitude, 26 responses
        # p.send(int.to_bytes(0b00010001_01001000_10000000_11000000, 4, 'big'))

        # Name, 26 responses
        p.send(int.to_bytes(0b00010000_01001000_10000000_11000000, 4, 'big'))

        # TLE, 26 responses
        # p.send(int.to_bytes(0b00010000_01000000_10000000_11000000, 4, 'big'))

        # Heartbeat, 26 responses
        # p.send(int.to_bytes(0b00011000_01000000_10000000_11000000, 4, 'big'))

        print('sent')
        not_sent = False

    packet_index += 1
