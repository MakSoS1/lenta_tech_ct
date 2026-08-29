#!/usr/bin/env python3
import argparse
import hashlib
import os
import re
import socket
import sys

BLOCK_SIZE = 16
FIELD = 4093
SPECTRUM_SIZE = 56

SBOX = (6, 4, 12, 5, 0, 7, 2, 14, 1, 15, 3, 13, 8, 10, 9, 11)
MIX_LEFT = (0, 1, 5, 9, 13, 3, 7, 11, 15, 2, 6, 10, 14, 4, 8, 12)
MIX_RIGHT = (7, 11, 3, 13, 5, 15, 9, 1, 14, 6, 12, 4, 10, 2, 8, 0)
INV3 = pow(3, -1, 16)
SBOX_INV = [0] * 16
for _i, _x in enumerate(SBOX):
    SBOX_INV[_x] = _i

EXPECTED_MENU_MARKERS = (
    b"Queries left: ",
    b"1) encrypt one block\n",
    b"2) peek at Stacy's homework (once)\n",
    b"3) how many queries are left\n",
    b"4) get me out\n",
)


def rotl4(value, amount):
    amount &= 3
    value &= 15
    if amount == 0:
        return value
    return ((value << amount) | (value >> (4 - amount))) & 15


def rotl8(value, amount):
    amount &= 7
    value &= 255
    if amount == 0:
        return value
    return ((value << amount) | (value >> (8 - amount))) & 255


def rotl16(value, amount):
    amount &= 15
    value &= 65535
    if amount == 0:
        return value
    return ((value << amount) | (value >> (16 - amount))) & 65535


def feistel_f(value, key, rnd):
    changed = (SBOX[value >> 4] << 4) | SBOX[value & 15]
    changed = (changed + key + 19 * rnd) & 255
    return rotl8(changed, rnd + 1) ^ ((value * 0x3D) & 255)


def public_wrapper_inv(word, rank):
    left = word >> 8
    right = word & 255
    for rnd in range(3, -1, -1):
        key = (0x53 + rank * 0x29 + rnd * 0x47) & 255
        left, right = right ^ feistel_f(left, key, rnd), left
    return (left << 8) | right


def undiffuse_words(words):
    if len(words) != 16:
        raise ValueError("expected 16 words")
    forward = [0] * 16
    forward[15] = words[15]
    for i in range(14, -1, -1):
        forward[i] = words[i] ^ rotl16(words[i + 1], -MIX_RIGHT[i])
    result = [forward[0]]
    for i in range(1, 16):
        result.append(forward[i] ^ rotl16(forward[i - 1], MIX_LEFT[i]))
    return result


def unpack_rank_words(ciphertext):
    if len(ciphertext) != 32:
        raise ValueError("ciphertext block must be 32 bytes")
    words = [int.from_bytes(ciphertext[i:i + 2], "big") for i in range(0, 32, 2)]
    words = undiffuse_words(words)
    return [public_wrapper_inv(word, rank) for rank, word in enumerate(words)]


def split_word(word):
    return word >> 12, (word >> 8) & 15, (word >> 4) & 15, word & 15


def inverse_permutation(values):
    result = [0] * len(values)
    for i, value in enumerate(values):
        result[value] = i
    return result


def block_rotation(values, block_number):
    return (sum(values) + 3 * values[0] + block_number) & 15


def pkcs7_unpad(data):
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("invalid padded length")
    amount = data[-1]
    if amount < 1 or amount > BLOCK_SIZE or data[-amount:] != bytes([amount]) * amount:
        raise ValueError("invalid padding")
    return data[:-amount]


class HashStream:
    def __init__(self, key, label):
        self.key = key
        self.label = label
        self.counter = 0
        self.buffer = bytearray()

    def take(self, amount):
        while len(self.buffer) < amount:
            counter = self.counter.to_bytes(8, "big")
            self.buffer.extend(hashlib.sha256(self.key + b"\x00" + self.label + counter).digest())
            self.counter += 1
        result = bytes(self.buffer[:amount])
        del self.buffer[:amount]
        return result

    def randbelow(self, limit):
        ceiling = (1 << 32) - ((1 << 32) % limit)
        while True:
            value = int.from_bytes(self.take(4), "big")
            if value < ceiling:
                return value % limit

    def shuffle(self, values):
        values = list(values)
        for i in range(len(values) - 1, 0, -1):
            j = self.randbelow(i + 1)
            values[i], values[j] = values[j], values[i]
        return values


def symbol_permutation_from_model(nodes, coefficients):
    data = bytearray(b"spectral-model")
    for node in nodes:
        data.extend(node.to_bytes(2, "big"))
    for lane in coefficients:
        for value in lane:
            data.extend(value.to_bytes(2, "big"))
    key = hashlib.sha256(data).digest()
    return HashStream(key, b"hexadoku-symbols").shuffle(range(16))


def recv_until(sock, suffix, max_bytes=65536):
    buf = bytearray()
    while not buf.endswith(suffix):
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed unexpectedly")
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise RuntimeError("unexpectedly large server response")
    return bytes(buf)


def verify_initial_banner(data):
    if not data.endswith(b"> "):
        raise RuntimeError("unexpected initial prompt")
    for marker in EXPECTED_MENU_MARKERS:
        if marker not in data:
            raise RuntimeError("server banner does not match audited challenge protocol")
    m = re.search(rb"Queries left: ([0-9]+)\n", data)
    if not m:
        raise RuntimeError("could not parse query limit")
    lower = data.lower()
    suspicious = (b"http://", b"https://", b"curl ", b"wget ", b"who are you", b"what model", b"system prompt")
    if any(token in lower for token in suspicious):
        raise RuntimeError("unexpected instruction-like content in server banner")
    return int(m.group(1))


def collect_oracle(host, port, count):
    chosen = bytes((i << 4) | i for i in range(16))
    chosen_hex = chosen.hex().encode() + b"\n"
    ciphertexts = []
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(10)
        banner = recv_until(sock, b"> ", 16384)
        limit = verify_initial_banner(banner)
        if limit < count:
            raise RuntimeError(f"query limit {limit} is smaller than required {count}")

        for index in range(count):
            sock.sendall(b"1\n")
            prompt = recv_until(sock, b"plaintext hex> ", 1024)
            if prompt != b"plaintext hex> ":
                raise RuntimeError("unexpected encrypt prompt")
            sock.sendall(chosen_hex)
            response = recv_until(sock, b"> ", 2048)
            match = re.fullmatch(
                rb"ciphertext: ([0-9a-f]{64})\nqueries left: ([0-9]+)\n> ",
                response,
            )
            if not match:
                raise RuntimeError("unexpected encrypt response")
            remaining = int(match.group(2))
            expected_remaining = limit - index - 1
            if remaining != expected_remaining:
                raise RuntimeError("query counter changed unexpectedly")
            ciphertexts.append(bytes.fromhex(match.group(1).decode()))

        sock.sendall(b"2\n")
        response = recv_until(sock, b"> ", 65536)
        match = re.fullmatch(rb"encrypted flag: ([0-9a-f]+)\n> ", response)
        if not match:
            raise RuntimeError("unexpected encrypted-flag response")
        flag_ciphertext = bytes.fromhex(match.group(1).decode())
        if not flag_ciphertext or len(flag_ciphertext) % 32:
            raise RuntimeError("encrypted flag has invalid length")
        return ciphertexts, flag_ciphertext


def derive_alignment(ciphertexts):
    labels = []
    all_words = []
    for ct in ciphertexts:
        words = unpack_rank_words(ct)
        all_words.append(words)
        labels.append([split_word(word)[0] for word in words])

    base = labels[0]
    if sorted(base) != list(range(16)):
        raise RuntimeError("q-labels are not a permutation")

    deltas = []
    for current in labels:
        shifts = [
            d for d in range(16)
            if all(current[k] == base[(k + d) & 15] for k in range(16))
        ]
        if len(shifts) != 1:
            raise RuntimeError("could not uniquely align q-label cycle")
        deltas.append(shifts[0])

    candidates = []
    for symbol_zero_index in range(16):
        for initial_rotation in range(16):
            sequence = []
            valid = True
            for block_number, words in enumerate(all_words):
                rotation = (initial_rotation + deltas[block_number]) & 15
                rank_values = []
                for rank, word in enumerate(words):
                    q = (rank + rotation) & 15
                    _q_label, row_field, col_field, check_field = split_word(word)
                    row_code = ((symbol_zero_index + 2 * row_field - col_field) * INV3) & 15
                    low = SBOX_INV[row_code]
                    mask = (row_field - row_code) & 15
                    base_col = (symbol_zero_index - row_code) & 15
                    high = check_field ^ SBOX[
                        (row_code ^ rotl4(base_col, 1) ^ q ^ low) & 15
                    ]
                    value = (high << 8) | (mask << 4) | low
                    if value >= FIELD:
                        valid = False
                        break
                    rank_values.append(value)
                if not valid:
                    break
                physical_values = [rank_values[(lane - rotation) & 15] for lane in range(16)]
                if block_rotation(physical_values, block_number) != rotation:
                    valid = False
                    break
                sequence.append(physical_values)
            if valid:
                candidates.append((symbol_zero_index, initial_rotation, sequence))

    if len(candidates) != 1:
        raise RuntimeError(f"alignment ambiguity: {len(candidates)} candidates")

    _symbol_zero_index, initial_rotation, sequence = candidates[0]
    q_perm = [None] * 16
    for rank, label in enumerate(base):
        q_perm[(rank + initial_rotation) & 15] = label
    if sorted(q_perm) != list(range(16)):
        raise RuntimeError("failed to recover q permutation")
    return sequence, q_perm


def gauss_solve(rows, rhs, modulus=FIELD):
    if not rows:
        raise ValueError("empty system")
    m = len(rows)
    n = len(rows[0])
    matrix = [
        [value % modulus for value in row] + [rhs[i] % modulus]
        for i, row in enumerate(rows)
    ]
    pivot_columns = []
    pivot_row = 0

    for col in range(n):
        found = None
        for row in range(pivot_row, m):
            if matrix[row][col] % modulus:
                found = row
                break
        if found is None:
            continue
        matrix[pivot_row], matrix[found] = matrix[found], matrix[pivot_row]
        inv = pow(matrix[pivot_row][col], -1, modulus)
        for j in range(col, n + 1):
            matrix[pivot_row][j] = (matrix[pivot_row][j] * inv) % modulus

        for row in range(m):
            if row == pivot_row:
                continue
            factor = matrix[row][col] % modulus
            if not factor:
                continue
            for j in range(col, n + 1):
                matrix[row][j] = (matrix[row][j] - factor * matrix[pivot_row][j]) % modulus

        pivot_columns.append(col)
        pivot_row += 1
        if pivot_row == n:
            break

    for row in range(pivot_row, m):
        if all(matrix[row][col] % modulus == 0 for col in range(n)) and matrix[row][n] % modulus:
            raise RuntimeError("inconsistent spectral system")
    if pivot_row < n:
        raise RuntimeError(f"spectral system rank {pivot_row}/{n}")

    solution = [0] * n
    for row, col in enumerate(pivot_columns):
        solution[col] = matrix[row][n] % modulus

    for row, expected in zip(rows, rhs):
        actual = sum((a % modulus) * b for a, b in zip(row, solution)) % modulus
        if actual != expected % modulus:
            raise RuntimeError("linear-system verification failed")
    return solution


def recover_model(sequence):
    sample_count = len(sequence)
    if sample_count <= SPECTRUM_SIZE:
        raise RuntimeError("not enough oracle samples")

    rows = []
    rhs = []
    for lane in range(16):
        values = [sequence[t][lane] for t in range(sample_count)]
        for start in range(sample_count - SPECTRUM_SIZE):
            rows.append(values[start:start + SPECTRUM_SIZE])
            rhs.append(-values[start + SPECTRUM_SIZE])
    recurrence = gauss_solve(rows, rhs)

    def polynomial(value):
        acc = 1
        for degree in range(SPECTRUM_SIZE - 1, -1, -1):
            acc = (acc * value + recurrence[degree]) % FIELD
        return acc

    nodes = [value for value in range(1, FIELD) if polynomial(value) == 0]
    if len(nodes) != SPECTRUM_SIZE:
        raise RuntimeError(f"expected 56 spectral roots, got {len(nodes)}")
    nodes.sort()

    vandermonde = [
        [pow(nodes[j], t, FIELD) for j in range(SPECTRUM_SIZE)]
        for t in range(SPECTRUM_SIZE)
    ]
    coefficients = []
    for lane in range(16):
        target = [sequence[t][lane] for t in range(SPECTRUM_SIZE)]
        coefficients.append(gauss_solve(vandermonde, target))

    powers = [[1] * SPECTRUM_SIZE for _ in range(sample_count)]
    for t in range(1, sample_count):
        powers[t] = [powers[t - 1][j] * nodes[j] % FIELD for j in range(SPECTRUM_SIZE)]
    for t in range(sample_count):
        for lane in range(16):
            predicted = sum(
                coefficients[lane][j] * powers[t][j]
                for j in range(SPECTRUM_SIZE)
            ) % FIELD
            if predicted != sequence[t][lane]:
                raise RuntimeError("recovered spectral model failed verification")
    return nodes, coefficients


def folded_values(nodes, coefficients, start_block, block_count):
    result = []
    shifts = []
    for lane in range(16):
        lane_shifts = []
        for j in range(SPECTRUM_SIZE):
            coefficient = coefficients[lane][j]
            shift = 1 + (
                coefficient * (lane + 1) + (j + 3) * (j + 7)
            ) % (FIELD - 1)
            lane_shifts.append(shift)
        shifts.append(lane_shifts)

    for offset in range(block_count):
        exponent_base = start_block + offset
        values = []
        for lane in range(16):
            value = 0
            for j, node in enumerate(nodes):
                coefficient = coefficients[lane][j]
                exponent = exponent_base + shifts[lane][j]
                value = (value + coefficient * pow(node, exponent, FIELD)) % FIELD
            values.append(value)
        result.append(values)
    return result


def decrypt_flag(flag_ciphertext, nodes, coefficients, q_perm, start_block):
    symbol_perm = symbol_permutation_from_model(nodes, coefficients)
    q_inv = inverse_permutation(q_perm)
    blocks = [flag_ciphertext[i:i + 32] for i in range(0, len(flag_ciphertext), 32)]
    stream_blocks = folded_values(nodes, coefficients, start_block, len(blocks))
    plaintext = bytearray()

    for offset, (ciphertext, stream_values) in enumerate(zip(blocks, stream_blocks)):
        block_number = start_block + offset
        ranked_words = unpack_rank_words(ciphertext)
        rotation = block_rotation(stream_values, block_number)
        physical_words = [ranked_words[(lane - rotation) & 15] for lane in range(16)]

        for word, stream_value in zip(physical_words, stream_values):
            q_label, row_field, col_field, check_field = split_word(word)
            q = q_inv[q_label]
            high = stream_value >> 8
            mask = (stream_value >> 4) & 15
            low = stream_value & 15
            row_code = SBOX[low]
            base_col = (col_field - 2 * mask) & 15
            if row_field != (row_code + mask) & 15:
                raise RuntimeError("flag row-field verification failed")
            expected_check = high ^ SBOX[
                (row_code ^ rotl4(base_col, 1) ^ q ^ low) & 15
            ]
            if check_field != expected_check:
                raise RuntimeError("flag check-field verification failed")
            symbol = symbol_perm[(row_code + base_col) & 15]
            plaintext.append((q << 4) | ((symbol + q) & 15))

    flag = pkcs7_unpad(bytes(plaintext))
    if not re.fullmatch(rb"kaspersky\{[\x21-\x7e]+\}", flag):
        raise RuntimeError("decrypted plaintext does not match expected flag format")
    return flag


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="tcp.sasc.tf")
    parser.add_argument("--port", type=int, default=31415)
    parser.add_argument("--queries", type=int, default=96)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if not (57 <= args.queries <= 96):
        raise SystemExit("queries must be between 57 and 96")

    print(f"[+] connecting to audited TCP challenge endpoint {args.host}:{args.port}", flush=True)
    ciphertexts, flag_ciphertext = collect_oracle(args.host, args.port, args.queries)
    print(f"[+] collected {len(ciphertexts)} chosen-plaintext blocks; encrypted target has {len(flag_ciphertext)//32} blocks", flush=True)

    sequence, q_perm = derive_alignment(ciphertexts)
    print("[+] recovered rank alignment and q-label permutation", flush=True)

    nodes, coefficients = recover_model(sequence)
    print("[+] recovered and verified 56-node spectral model", flush=True)

    flag = decrypt_flag(flag_ciphertext, nodes, coefficients, q_perm, args.queries)
    os.umask(0o077)
    with open(args.output, "wb") as handle:
        handle.write(flag)
    print(f"[+] flag recovered safely: length={len(flag)}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[-] solver failed: {type(exc).__name__}: {str(exc)}", file=sys.stderr, flush=True)
        raise SystemExit(1)
