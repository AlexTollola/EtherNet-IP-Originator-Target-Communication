import socket
import struct
import csv

VERBOSE = False

EIP_PORT = 44818
REGISTER_SESSION = 0x65
UNREGISTER_SESSION = 0x66
SEND_RR_DATA = 0x6F
GET_ATTRIBUTE_SINGLE = 0x0E
SET_ATTRIBUTE_SINGLE = 0x10

CSV_PATH = "AttributeList.csv"

# Load attributes from CSV

def load_attributes(file_path):
    attrs = []
    with open(file_path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            attrs.append({
                'class': int(row['Class'], 16),
                'instance': int(row['Instance'], 16),
                'attribute': int(row['Attribute'], 16),
                'name': row['Name'].strip(),
                'type': row['Type'].strip(),
                'access': row['Access Type'].strip()
            })
    return attrs

# Encode/decode helpers

def encode_value(val, typ):
    if typ == 'U8':
        return struct.pack('<B', int(val))
    if typ == 'U16':
        return struct.pack('<H', int(val))
    if typ == 'U32':
        return struct.pack('<I', int(val))
    if typ == 'I8':
        return struct.pack('<b', int(val))
    if typ == 'I16':
        return struct.pack('<h', int(val))
    if typ == 'I32':
        return struct.pack('<i', int(val))
    if typ == 'F32':
        return struct.pack('<f', float(val))
    raise ValueError('unknown type')


def decode_value(buf, typ):
    if typ == 'U8':
        return struct.unpack('<B', buf)[0]
    if typ == 'U16':
        return struct.unpack('<H', buf)[0]
    if typ == 'U32':
        return struct.unpack('<I', buf)[0]
    if typ == 'I8':
        return struct.unpack('<b', buf)[0]
    if typ == 'I16':
        return struct.unpack('<h', buf)[0]
    if typ == 'I32':
        return struct.unpack('<i', buf)[0]
    if typ == 'F32':
        return struct.unpack('<f', buf)[0]
    return buf

# Build CIP path bytes

def build_path(cls, inst, attr):
    path = bytearray()
    path.extend([0x20, cls & 0xFF])
    if inst <= 0xFF:
        path.extend([0x24, inst & 0xFF])
    else:
        path.append(0x25)
        path.extend(struct.pack('<H', inst))
    path.extend([0x30, attr & 0xFF])
    if len(path) % 2:
        path.append(0)
    return bytes(path), len(path) // 2

# Build CIP requests

def build_get(cls, inst, attr):
    path, words = build_path(cls, inst, attr)
    return bytes([GET_ATTRIBUTE_SINGLE, words]) + path


def build_set(cls, inst, attr, value):
    path, words = build_path(cls, inst, attr)
    return bytes([SET_ATTRIBUTE_SINGLE, words]) + path + value

# ENIP SendRRData helper

def build_rr(session, cip):
    address_item = struct.pack('<HH', 0x0000, 0)
    data_item = struct.pack('<HH', 0x00B2, len(cip)) + cip
    cpf = struct.pack('<IHH', 0, 0, 2) + address_item + data_item
    header = struct.pack('<HHII8sI', SEND_RR_DATA, len(cpf), session, 0, b'\x00'*8, 0)
    return header + cpf

# Session handling

def register_session(sock):
    req = struct.pack('<HHIIQI', REGISTER_SESSION, 4, 0, 0, 0, 0) + struct.pack('<HH', 1, 0)
    sock.sendall(req)
    data = sock.recv(1024)
    if len(data) < 24:
        raise RuntimeError('bad register session reply')
    return struct.unpack_from('<I', data, 4)[0]


def unregister_session(sock, session):
    hdr = struct.pack('<HHII8sI', UNREGISTER_SESSION, 0, session, 0, b'\x00'*8, 0)
    sock.sendall(hdr)


def send_cip(sock, session, request):
    payload = build_rr(session, request)
    if VERBOSE:
        print(f"--> {payload.hex()}")
    sock.sendall(payload)
    data = sock.recv(1024)
    if VERBOSE:
        print(f"<-- {data.hex()}")
    return data

# Parse CIP response value

def parse_cip_response(data, typ):
    """Extract and decode the value from a GET response."""
    # 24 bytes ENIP header + 16 bytes CPF items before the CIP payload
    offset = 40
    if len(data) < offset + 4:
        return None
    cip = data[offset:]
    if len(cip) < 4:
        return None
    size = len(encode_value(0, typ))
    if len(cip) < 4 + size:
        return None
    return decode_value(cip[4:4 + size], typ)


def main():
    attrs = load_attributes(CSV_PATH)
    controls = [a for a in attrs if a['access'].lower() == 'control']
    monitors = [a for a in attrs if a['access'].lower() == 'monitor']

    host = input('Enter target IP (default 127.0.0.1): ') or '127.0.0.1'
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, EIP_PORT))
    session = register_session(sock)

    while True:
        print('\nSelect an option:')
        print(' 1) Change a Control attribute')
        print(' 2) Show Monitor attribute values')
        print(' 3) Quit and Forward Close')
        choice = input('> ').strip()
        if choice == '1':
            for i, a in enumerate(controls, 1):
                print(f" {i}) {a['name']} (Class 0x{a['class']:02X}, Instance 0x{a['instance']:04X}, Attribute 0x{a['attribute']:02X}) [{a['type']}]")
            sel = input('Select attribute: ').strip()
            if not sel.isdigit() or not (1 <= int(sel) <= len(controls)):
                print('Invalid selection.')
                continue
            attr = controls[int(sel)-1]
            val = input('Enter new value: ')
            data = encode_value(val, attr['type'])
            if VERBOSE:
                print(
                    f"Setting {attr['name']} (class 0x{attr['class']:02X}, instance 0x{attr['instance']:04X}, attribute 0x{attr['attribute']:02X}) to {val}"
                )
            send_cip(
                sock,
                session,
                build_set(
                    attr['class'],
                    attr['instance'],
                    attr['attribute'],
                    data,
                ),
            )
            print('Set sent.')
        elif choice == '2':
            for i, a in enumerate(monitors, 1):
                print(f" {i}) {a['name']} (Class 0x{a['class']:02X}, Instance 0x{a['instance']:04X}, Attribute 0x{a['attribute']:02X}) [{a['type']}]")
            sel = input('Select attribute or 0 for all: ').strip()
            if sel == '0':
                targets = monitors
            elif sel.isdigit() and 1 <= int(sel) <= len(monitors):
                targets = [monitors[int(sel)-1]]
            else:
                print('Invalid selection.')
                continue
            for a in targets:
                if VERBOSE:
                    print(f"Requesting {a['name']} (class 0x{a['class']:02X}, instance 0x{a['instance']:04X}, attribute 0x{a['attribute']:02X})")
                resp = send_cip(sock, session, build_get(a['class'], a['instance'], a['attribute']))
                val = parse_cip_response(resp, a['type'])
                print(f"{a['name']}: {val}")
        elif choice == '3':
            unregister_session(sock, session)
            sock.close()
            break
        else:
            print('Invalid option.')

if __name__ == '__main__':
    main()
