#!/usr/bin/env python

import os
import socket
import struct
import logging
import re
import requests
import sys
import io

# Configuration
TFTP_ROOT_DIR = "/tftp"
HTTP_ENDPOINT = "http://sas.labma.ru/cisco/"
DEFAULT_BLOCKSIZE = 512
ALLOWED_FILENAME_REGEX = re.compile(r'^cisco/[a-zA-Z0-9_\-\.]+-confg$')
SOCKET_TIMEOUT = 10  # Таймаут для сокета в секундах

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# TFTP opcodes
OP_RRQ  = 1  # Read request
OP_WRQ  = 2  # Write request
OP_DATA = 3  # Data packet
OP_ACK  = 4  # Acknowledgment
OP_ERROR = 5 # Error
OP_OACK = 6  # Option acknowledgment

def send_file_to_http(filename, file_data):
    """Send the raw file data to the HTTP endpoint using POST."""
    try:
        headers = {
            'Content-Type': 'application/octet-stream',
            'X-Filename': filename,
        }
        response = requests.post(f"{HTTP_ENDPOINT}?{os.path.basename(filename)}", data=file_data, headers=headers, timeout=SOCKET_TIMEOUT)
        response.raise_for_status()
        logger.info(f"File {filename} sent to {HTTP_ENDPOINT} via POST. Response: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to POST {filename}: {e}")

def handle_tftp(sock):
    """Handle TFTP requests on the given socket."""
    sock.settimeout(SOCKET_TIMEOUT)  # Устанавливаем таймаут для сокета

    try:
        data, addr = sock.recvfrom(1024)
    except socket.timeout:
        logger.error("Socket timeout while waiting for request")
        return
    except socket.error as e:
        logger.error(f"Socket error while waiting for request: {e}")
        return

    opcode = data[:2]

    if opcode == struct.pack('!H', OP_RRQ):
        # Handle download (RRQ)
        filename = data[2:].decode('utf-8').split('\x00')[0]
        filepath = os.path.join(TFTP_ROOT_DIR, filename)
        if not os.path.exists(filepath):
            logger.warning(f"File {filename} not found.")
            sock.sendto(struct.pack('!H', OP_ERROR) + b'\x00\x01File not found\x00', addr)
            return

        # Check for TFTP options (e.g., blksize)
        options = {}
        parts = data[2:].decode('utf-8').split('\x00')
        for i in range(len(parts)):
            if parts[i].lower() == 'blksize':
                try:
                    options['blksize'] = int(parts[i+1])
                except (IndexError, ValueError):
                    pass

        # Negotiate block size
        blksize = options.get('blksize', DEFAULT_BLOCKSIZE)
        if blksize > 65464:  # Maximum allowed block size per RFC 2348
            blksize = DEFAULT_BLOCKSIZE

        # Send OACK if block size was negotiated
        if 'blksize' in options:
            oack = struct.pack('!H', OP_OACK) + b'blksize\x00' + str(blksize).encode() + b'\x00'
            sock.sendto(oack, addr)

        # Send file in DATA packets with negotiated block size
        with open(filepath, 'rb') as f:
            block = 1
            while True:
                chunk = f.read(blksize)
                if not chunk:
                    break
                packet = struct.pack('!H', OP_DATA) + struct.pack('!H', block) + chunk
                sock.sendto(packet, addr)
                block += 1

    elif opcode == struct.pack('!H', OP_WRQ):
        # Handle upload (WRQ)
        filename = data[2:].decode('utf-8').split('\x00')[0]
        if not ALLOWED_FILENAME_REGEX.match(filename):
            logger.warning(f"Filename {filename} is not allowed.")
            sock.sendto(struct.pack('!H', OP_ERROR) + b'\x00\x02Access denied\x00', addr)
            return

        # Check for TFTP options (e.g., blksize)
        options = {}
        parts = data[2:].decode('utf-8').split('\x00')
        for i in range(len(parts)):
            if parts[i].lower() == 'blksize':
                try:
                    options['blksize'] = int(parts[i+1])
                except (IndexError, ValueError):
                    pass

        # Negotiate block size
        blksize = options.get('blksize', DEFAULT_BLOCKSIZE)
        if blksize > 65464:  # Maximum allowed block size per RFC 2348
            blksize = DEFAULT_BLOCKSIZE

        # Send OACK if block size was negotiated
        if 'blksize' in options:
            oack = struct.pack('!H', OP_OACK) + b'blksize\x00' + str(blksize).encode() + b'\x00'
            sock.sendto(oack, addr)

        file_data = io.BytesIO()
        block = 0
        while True:
            try:
                data, _ = sock.recvfrom(blksize + 4)  # +4 for opcode and block number
            except socket.timeout:
                logger.error("Socket timeout while waiting for data block")
                break
            except socket.error as e:
                logger.error(f"Socket error during upload: {e}")
                break

            opcode = data[:2]
            if opcode == struct.pack('!H', OP_DATA):
                block_num = struct.unpack('!H', data[2:4])[0]
                if block_num == block + 1:
                    chunk = data[4:]
                    file_data.write(chunk)
                    ack = struct.pack('!H', OP_ACK) + struct.pack('!H', block_num)
                    sock.sendto(ack, addr)
                    block = block_num
                    if len(chunk) < blksize:
                        break
                else:
                    ack = struct.pack('!H', OP_ACK) + struct.pack('!H', block)
                    sock.sendto(ack, addr)
            else:
                break

        logger.info(f"File {filename} uploaded via TFTP in {block} blocks.")
        send_file_to_http(filename, file_data.getvalue())

if __name__ == "__main__":
    os.makedirs(TFTP_ROOT_DIR, exist_ok=True)

    # Check if systemd passed a socket
    if os.environ.get('LISTEN_FDS', '0') != '1':
        logger.error("No socket passed by systemd.")
        sys.exit(1)

    # Use the socket file descriptor passed by systemd
    sock = socket.socket(fileno=3)
    logger.info("Starting TFTP server with systemd socket activation...")
    handle_tftp(sock)
