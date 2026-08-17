#!/usr/bin/env python

import os
import socket
import struct
import logging
import re
import requests
import sys
import io
import time

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

def resolve_file_path(filename):
    """Resolve a requested TFTP path safely inside TFTP_ROOT_DIR.

    Handles absolute-looking requests (e.g. "/cisco/router-confg") and
    prevents directory traversal ("../") outside the root directory.
    Returns the absolute path or None if it escapes the root.
    """
    # Normalize separators and strip leading slashes so absolute requests
    # are treated as relative to the TFTP root directory.
    filename = filename.replace('\\', '/').lstrip('/')

    root = os.path.realpath(TFTP_ROOT_DIR)
    fullpath = os.path.realpath(os.path.join(root, filename))

    try:
        if os.path.commonpath([root, fullpath]) != root:
            return None
    except ValueError:
        return None

    return fullpath

def _send_and_wait_ack(sock, addr, packet, expected_block, retries=5, timeout=3):
    """Send a TFTP packet and wait for the matching ACK.

    Retransmits the packet on timeout and ignores out-of-order ACKs.
    Returns True when the expected ACK is received, False on error or
    after exhausting retries.
    """
    for _ in range(retries):
        try:
            sock.sendto(packet, addr)
        except socket.error as e:
            logger.error(f"Socket error while sending: {e}")
            return False

        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                break  # no ACK before the deadline, retransmit
            except socket.error as e:
                logger.error(f"Socket error while waiting for ACK: {e}")
                return False

            if len(data) < 4:
                continue

            opcode = data[:2]
            if opcode == struct.pack('!H', OP_ERROR):
                if len(data) >= 4:
                    err_code = struct.unpack('!H', data[2:4])[0]
                    err_msg = data[4:].split(b'\x00', 1)[0].decode('utf-8', errors='replace')
                    logger.error(f"Client sent error code {err_code}: {err_msg}")
                else:
                    logger.error("Client sent malformed error packet")
                return False
            if opcode == struct.pack('!H', OP_ACK):
                ack_block = struct.unpack('!H', data[2:4])[0]
                if ack_block == expected_block:
                    return True

    logger.warning(f"Giving up: no ACK for block {expected_block} after {retries} attempts")
    return False

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
        filepath = resolve_file_path(filename)
        if filepath is None or not os.path.isfile(filepath):
            logger.warning(f"File {filename} not found.")
            sock.sendto(struct.pack('!H', OP_ERROR) + b'\x00\x01File not found\x00', addr)
            return

        logger.info(f"Client {addr[0]}:{addr[1]} downloading {filename}")

        # Parse TFTP options (blksize, tsize).
        options = {}
        parts = data[2:].decode('utf-8').split('\x00')
        for i in range(len(parts)):
            name = parts[i].lower()
            if name in ('blksize', 'tsize'):
                try:
                    options[name] = int(parts[i + 1])
                except (IndexError, ValueError):
                    pass

        # Negotiate block size
        blksize = options.get('blksize', DEFAULT_BLOCKSIZE)
        if blksize > 65464:  # Maximum allowed block size per RFC 2348
            blksize = DEFAULT_BLOCKSIZE

        # Open the file before ACKing so permission errors are reported early.
        try:
            f = open(filepath, 'rb')
        except OSError as e:
            logger.error(f"Cannot open {filepath}: {e}")
            sock.sendto(struct.pack('!H', OP_ERROR) + b'\x00\x02Access violation\x00', addr)
            return

        # If options were requested, negotiate them via OACK and wait for
        # ACK block 0 before sending any DATA (RFC 2347/2349).
        if options:
            oack_fields = []
            if 'blksize' in options:
                oack_fields.append(b'blksize\x00' + str(blksize).encode() + b'\x00')
            if 'tsize' in options:
                oack_fields.append(b'tsize\x00' + str(os.path.getsize(filepath)).encode() + b'\x00')
            if oack_fields:
                oack = struct.pack('!H', OP_OACK) + b''.join(oack_fields)
                if not _send_and_wait_ack(sock, addr, oack, 0):
                    f.close()
                    return

        # Stream the file one block at a time, waiting for the ACK of each
        # block before reading the next one.
        block = 1
        data_sent = False
        last_was_full = False
        try:
            while True:
                chunk = f.read(blksize)
                if chunk == b'':
                    break
                packet = struct.pack('!H', OP_DATA) + struct.pack('!H', block) + chunk
                if not _send_and_wait_ack(sock, addr, packet, block):
                    return
                data_sent = True
                last_was_full = (len(chunk) == blksize)
                if not last_was_full:
                    break
                # Block numbers are 16-bit and wrap around after 65535 (RFC 2348).
                if block == 65535:
                    logger.info(f"Block number cycled to 0 after 65535 for {filename}")
                block = (block + 1) % 65536
        finally:
            f.close()

        # Send a final empty DATA block when the file was empty or ended on a
        # block boundary (RFC 1350).
        if not data_sent or last_was_full:
            packet = struct.pack('!H', OP_DATA) + struct.pack('!H', block) + b''
            if not _send_and_wait_ack(sock, addr, packet, block):
                return

    elif opcode == struct.pack('!H', OP_WRQ):
        # Handle upload (WRQ)
        filename = data[2:].decode('utf-8').split('\x00')[0]

        logger.info(f"Client {addr[0]}:{addr[1]} uploading {filename}")

        # Files matching the mask are pushed to the HTTP endpoint, everything
        # else is stored locally as a regular TFTP upload.
        upload_to_http = bool(ALLOWED_FILENAME_REGEX.match(filename))

        # Prepare the destination before the transfer starts so we can report
        # an error immediately if the local file cannot be created.
        out_file = None
        file_data = None
        if upload_to_http:
            file_data = io.BytesIO()
        else:
            local_filepath = resolve_file_path(filename)
            if local_filepath is None:
                logger.warning(f"Filename {filename} is not allowed.")
                sock.sendto(struct.pack('!H', OP_ERROR) + b'\x00\x02Access denied\x00', addr)
                return
            try:
                parent = os.path.dirname(local_filepath) or '.'
                os.makedirs(parent, exist_ok=True)
                out_file = open(local_filepath, 'wb')
            except OSError as e:
                logger.error(f"Cannot create {local_filepath}: {e}")
                sock.sendto(struct.pack('!H', OP_ERROR) + b'\x00\x02Access violation\x00', addr)
                return

        # Parse TFTP options (blksize, tsize).
        options = {}
        parts = data[2:].decode('utf-8').split('\x00')
        for i in range(len(parts)):
            name = parts[i].lower()
            if name in ('blksize', 'tsize'):
                try:
                    options[name] = int(parts[i + 1])
                except (IndexError, ValueError):
                    pass

        # Negotiate block size
        blksize = options.get('blksize', DEFAULT_BLOCKSIZE)
        if blksize > 65464:  # Maximum allowed block size per RFC 2348
            blksize = DEFAULT_BLOCKSIZE

        block = 0

        # Send OACK for requested options or an empty ACK otherwise.
        if options:
            oack_fields = []
            if 'blksize' in options:
                oack_fields.append(b'blksize\x00' + str(blksize).encode() + b'\x00')
            if 'tsize' in options:
                # The server does not know the final size of an upload yet.
                oack_fields.append(b'tsize\x00' + b'0\x00')
            oack = struct.pack('!H', OP_OACK) + b''.join(oack_fields)
        else:
            oack = struct.pack('!H', OP_ACK) + struct.pack('!H', block)

        sock.sendto(oack, addr)

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
                if block_num == (block + 1) % 65536:
                    if block == 65535:
                        logger.info(f"Block number cycled to 0 after 65535 for {filename}")
                    chunk = data[4:]
                    try:
                        if out_file is not None:
                            out_file.write(chunk)
                        else:
                            file_data.write(chunk)
                    except OSError as e:
                        logger.error(f"Cannot write upload: {e}")
                        sock.sendto(struct.pack('!H', OP_ERROR) + b'\x00\x03Disk full or allocation exceeded\x00', addr)
                        if out_file is not None:
                            out_file.close()
                        return
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

        if upload_to_http:
            logger.info(f"File {filename} uploaded via TFTP in {block} blocks.")
            send_file_to_http(filename, file_data.getvalue())
        else:
            out_file.close()
            logger.info(f"File {filename} saved to {local_filepath} in {block} blocks.")

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
