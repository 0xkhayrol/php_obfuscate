#!/usr/bin/env python3

import argparse
import base64
import os
import random
import string
import sys
from textwrap import dedent


def rand_bytes_hex(n):
    return os.urandom(n).hex()


def rand_ident(n=10):
    return ''.join(random.choice(string.ascii_letters) for _ in range(n))


def xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    k = key
    klen = len(k)
    for i, b in enumerate(data):
        out[i] = b ^ k[i % klen]
    return bytes(out)


def rotate_left_byte(b: int, n: int) -> int:
    return ((b << n) & 0xFF) | ((b & 0xFF) >> (8 - n))


def rotate_right_byte(b: int, n: int) -> int:
    return ((b & 0xFF) >> n) | ((b << (8 - n)) & 0xFF)


def apply_transforms(data: bytes, key1: bytes, key2: bytes, rot_n: int) -> bytes:
    s = xor_bytes(data, key1)
    s = s[::-1]
    s = bytes(rotate_left_byte(b, rot_n) for b in s)
    s = xor_bytes(s, key2)
    s = bytes((~b) & 0xFF for b in s)
    return s


def chunk_b64_parts(b: bytes, chunk_size=80):
    s = base64.b64encode(b).decode('ascii')
    return [s[i:i+chunk_size] for i in range(0, len(s), chunk_size)]


def php_array_literal(parts):
    quoted = [f"'{p}'" for p in parts]
    return ", ".join(quoted)


def build_php_stub(b64_parts, key1_hex, key2_hex, rot_n, no_eval=False, out_decoded=None):
    A = rand_ident(8)
    B = rand_ident(8)
    K1 = rand_ident(7)
    K2 = rand_ident(7)
    F_imp = rand_ident(10)
    F_xor = rand_ident(9)
    F_rot = rand_ident(9)
    F_write = rand_ident(10)
    arr = php_array_literal(b64_parts)
    out_fname = out_decoded if out_decoded else ('decoded_' + rand_ident(6) + '.php')

    stub = "<?php\n"
    stub += f"${A} = array({arr});\n"
    stub += f"${K1} = '{key1_hex}';\n"
    stub += f"${K2} = '{key2_hex}';\n"
    stub += f"${B} = {rot_n};\n\n"

    stub += dedent(f"""
    function {F_imp}($arr) {
        return base64_decode(implode('', $arr));
    }

    function {F_xor}($data, $hexkey) {
        $k = hex2bin($hexkey);
        $out = '';
        $klen = strlen($k);
        $dlen = strlen($data);
        for ($i=0; $i<$dlen; $i++) {
            $out .= chr(ord($data[$i]) ^ ord($k[$i % $klen]));
        }
        return $out;
    }

    function {F_rot}($data, $n, $dir = 'r') {
        $out = '';
        $dlen = strlen($data);
        for ($i=0; $i<$dlen; $i++) {
            $b = ord($data[$i]) & 0xFF;
            if ($dir === 'r') {
                $b = (($b >> $n) | (($b << (8 - $n)) & 0xFF)) & 0xFF;
            } else {
                $b = ((($b << $n) & 0xFF) | ($b >> (8 - $n))) & 0xFF;
            }
            $out .= chr($b);
        }
        return $out;
    }

    function {F_write}($fname, $payload) {
        $tmp = sys_get_temp_dir() . '/' . uniqid('t', true) . '.php';
        if (@file_put_contents($tmp, $payload) !== false) {
            @chmod($tmp, 0640);
            if (@rename($tmp, $fname)) {
                @include_once($fname);
                return true;
            }
        }
        @file_put_contents($fname, $payload);
        @include_once($fname);
        return true;
    }
    """)

    stub += "\n"
    stub += "try {\n"
    stub += f"    $enc = {F_imp}(${A});\n"
    stub += "    $s = '';\n"
    stub += "    for ($i=0;$i<strlen($enc);$i++) { $s .= chr((~ord($enc[$i])) & 0xFF); }\n"
    stub += f"    $s = {F_xor}($s, ${K2});\n"
    stub += f"    $s = {F_rot}($s, ${B}, 'r');\n"
    stub += "    $s = strrev($s);\n"
    stub += f"    $s = {F_xor}($s, ${K1});\n\n"
    if no_eval:
        stub += f"    {F_write}('{out_fname}', $s);\n"
        stub += "    exit;\n"
    else:
        stub += "    $tmp = sys_get_temp_dir() . '/' . uniqid('p', true) . '.php';\n"
        stub += "    if (@file_put_contents($tmp, $s) !== false) {\n"
        stub += "        @include_once($tmp);\n"
        stub += "        @unlink($tmp);\n"
        stub += "        exit;\n"
        stub += "    }\n"
        stub += "    @eval($s);\n"
        stub += "    exit;\n"

    stub += "\n} catch (Exception $e) { exit; }\n?>"
    return stub


def parse_args():
    p = argparse.ArgumentParser(description="Multi-transform PHP encoder (pure-PHP decode)")
    p.add_argument('-i', '--input', required=True, help='Input PHP file')
    p.add_argument('-o', '--output', required=False, help='Output stub filename')
    p.add_argument('--keylen1', type=int, default=16)
    p.add_argument('--keylen2', type=int, default=16)
    p.add_argument('--rot', type=int, default=3)
    p.add_argument('--chunksize', type=int, default=80)
    p.add_argument('--no-eval', dest='no_eval', action='store_true')
    return p.parse_args()


def main():
    opts = parse_args()
    if not os.path.isfile(opts.input):
        print("Input not found:", opts.input); sys.exit(1)
    if opts.rot < 1 or opts.rot > 7:
        print("rot must be between 1 and 7"); sys.exit(1)

    with open(opts.input, 'rb') as f:
        data = f.read()

    key1 = os.urandom(opts.keylen1)
    key2 = os.urandom(opts.keylen2)
    transformed = apply_transforms(data, key1, key2, opts.rot)
    parts = chunk_b64_parts(transformed, chunk_size=opts.chunksize)

    key1_hex = key1.hex()
    key2_hex = key2.hex()

    out = opts.output if opts.output else f"output_{os.path.basename(opts.input)}_1.php"
    out_decoded = 'decoded_' + rand_ident(6) + '.php'
    phpstub = build_php_stub(parts, key1_hex, key2_hex, opts.rot, no_eval=opts.no_eval, out_decoded=out_decoded)

    with open(out, 'w', encoding='utf-8') as fo:
        fo.write(phpstub)

    print("Done.")
    print("Input:", opts.input)
    print("Output stub:", out)
    print("Decoded filename (if --no-eval used):", out_decoded)
    print("Keep these safe (hex keys):")
    print(" key1 (hex):", key1_hex)
    print(" key2 (hex):", key2_hex)
    print(" rotate:", opts.rot)

if __name__ == '__main__':
    main()
