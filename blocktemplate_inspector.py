#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import ssl
import time
import hashlib
from typing import Any, Dict, List, Optional

# =============================
#  Utils affichage / décodage
# =============================

def hex_to_ascii_preview(hex_str: str, max_len: int = 80) -> str:
    try:
        b = bytes.fromhex(hex_str)
    except ValueError:
        return "<hex invalide>"

    # Filtre les caractères imprimables
    s = "".join(chr(c) if 32 <= c <= 126 else "." for c in b)
    if len(s) > max_len:
        s = s[:max_len] + "..."
    return s


def le_hex_to_be_hex(hex_str: str) -> str:
    """Convertit un hex little-endian en big-endian (utilisé notamment pour prevhash)."""
    try:
        b = bytes.fromhex(hex_str)
        return b[::-1].hex()
    except ValueError:
        return hex_str


def pretty_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)


# =============================
#  Helpers base58 / bech32 / scripts
# =============================

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b: bytes) -> str:
    n_zeros = len(b) - len(b.lstrip(b"\0"))
    num = int.from_bytes(b, "big")
    res = ""
    while num > 0:
        num, rem = divmod(num, 58)
        res = ALPHABET[rem] + res
    return "1" * n_zeros + res


def b58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum)


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode_segwit_address(hrp: str, witver: int, witprog: bytes) -> str:
    data = [witver] + convertbits(list(witprog), 8, 5, True)
    return bech32_encode(hrp, data)


def script_to_address(script_hex: str, network: str = "main") -> Optional[str]:
    """
    Tente de décoder les scripts de type :
      - P2PKH
      - P2SH
      - P2WPKH / P2WSH (v0)
      - P2TR (v1)
    Retourne l'adresse string ou None si non géré.
    """
    try:
        script = bytes.fromhex(script_hex)
    except ValueError:
        return None

    # P2PKH : OP_DUP OP_HASH160 0x14 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if (
        len(script) == 25
        and script[0] == 0x76
        and script[1] == 0xA9
        and script[2] == 0x14
        and script[-2] == 0x88
        and script[-1] == 0xAC
    ):
        h160 = script[3:23]
        prefix = b"\x00" if network == "main" else b"\x6F"  # mainnet / testnet
        return b58check_encode(prefix + h160)

    # P2SH : OP_HASH160 0x14 <20 bytes> OP_EQUAL
    if len(script) == 23 and script[0] == 0xA9 and script[1] == 0x14 and script[-1] == 0x87:
        h160 = script[2:22]
        prefix = b"\x05" if network == "main" else b"\xC4"
        return b58check_encode(prefix + h160)

    # P2WPKH / P2WSH (v0) : 0x00 0x14/0x20 <prog>
    if len(script) in (22, 34) and script[0] == 0x00 and script[1] in (0x14, 0x20):
        witver = 0
        witprog = script[2:]
        hrp = "bc" if network == "main" else "tb"
        return encode_segwit_address(hrp, witver, witprog)

    # P2TR (v1) : OP_1 0x20 <32-byte>
    if len(script) == 34 and script[0] == 0x51 and script[1] == 0x20:
        witver = 1
        witprog = script[2:]
        hrp = "bc" if network == "main" else "tb"
        return encode_segwit_address(hrp, witver, witprog)

    return None


def read_varint(b: bytes, offset: int):
    prefix = b[offset]
    if prefix < 0xFD:
        return prefix, offset + 1
    elif prefix == 0xFD:
        return int.from_bytes(b[offset + 1 : offset + 3], "little"), offset + 3
    elif prefix == 0xFE:
        return int.from_bytes(b[offset + 1 : offset + 5], "little"), offset + 5
    else:
        return int.from_bytes(b[offset + 1 : offset + 9], "little"), offset + 9


def parse_tx_outputs(tx_hex: str):
    """
    Parse une transaction (y compris format segwit) et renvoie la liste des sorties :
      [(value_satoshis, scriptPubKey_hex), ...]
    """
    data = bytes.fromhex(tx_hex)
    offset = 0

    # version
    if len(data) < 4:
        raise ValueError("TX trop courte")
    offset += 4

    # segwit marker/flag ?
    if offset + 2 <= len(data) and data[offset] == 0x00 and data[offset + 1] != 0x00:
        offset += 2  # on ignore le marker/flag, on n'utilise pas les witness ici

    # inputs
    n_inputs, offset = read_varint(data, offset)
    for _ in range(n_inputs):
        offset += 32  # prev txid
        offset += 4   # prev vout
        script_len, offset = read_varint(data, offset)
        offset += script_len
        offset += 4  # sequence

    # outputs
    n_outputs, offset = read_varint(data, offset)
    outputs = []
    for _ in range(n_outputs):
        value = int.from_bytes(data[offset : offset + 8], "little")
        offset += 8
        script_len, offset = read_varint(data, offset)
        script = data[offset : offset + script_len]
        offset += script_len
        outputs.append((value, script.hex()))

    return outputs


# =============================
#  Client Stratum minimal
# =============================

class StratumClient:
    def __init__(self, host: str, port: int, user: str, password: str, use_tls: bool = False, timeout: int = 10):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.use_tls = use_tls
        self.timeout = timeout

        self.socket: Optional[socket.socket] = None
        self.fh = None  # file-like pour readline
        self._id_counter = 1

        # Infos d'extranonce reçues dans mining.set_extranonce
        self.extranonce1: Optional[str] = None
        self.extranonce2_size: Optional[int] = None

    def _next_id(self) -> int:
        self._id_counter += 1
        return self._id_counter

    def connect(self):
        print(f"[+] Connexion au serveur Stratum {self.host}:{self.port} (TLS={self.use_tls})")
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            context = ssl.create_default_context()
            # Option permettant de désactiver la vérification TLS pour les environnements non standard
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            s = context.wrap_socket(s, server_hostname=self.host)

        self.socket = s
        self.fh = s.makefile("rwb", buffering=0)
        print("[+] Connexion établie.\n")

    def send_message(self, method: str, params: List[Any], msg_id: Optional[int] = None):
        if msg_id is None:
            msg_id = self._next_id()
        msg = {
            "id": msg_id,
            "method": method,
            "params": params,
        }
        line = (json.dumps(msg) + "\n").encode("utf-8")
        assert self.fh is not None
        self.fh.write(line)
        print(f"--> Requête {method} envoyée (id={msg_id})")

    def read_message(self) -> Dict[str, Any]:
        assert self.fh is not None
        line = self.fh.readline()
        if not line:
            raise ConnectionError("Connexion fermée par le serveur Stratum.")
        try:
            msg = json.loads(line.decode("utf-8").strip())
        except json.JSONDecodeError:
            print(f"[!] Ligne JSON invalide : {line!r}", file=sys.stderr)
            return {}
        return msg

    def subscribe_and_authorize(self):
        # Étape 1 : mining.subscribe
        self.send_message("mining.subscribe", [])
        sub_id = self._id_counter

        # Étape 2 : mining.authorize
        self.send_message("mining.authorize", [self.user, self.password])
        auth_id = self._id_counter

        # Lecture des réponses pour récupérer les paramètres d'extranonce
        got_subscribe = False
        got_auth = False

        start = time.time()
        while not (got_subscribe and got_auth):
            if time.time() - start > self.timeout:
                raise TimeoutError("Délai dépassé lors de la phase subscribe/authorize.")

            msg = self.read_message()
            if not msg:
                continue

            if msg.get("id") == sub_id:
                got_subscribe = True
                print("\n<-- mining.subscribe :")
                print(pretty_json(msg))

                result = msg.get("result")
                if isinstance(result, list) and len(result) >= 2:
                    try:
                        self.extranonce1 = result[1]
                        self.extranonce2_size = int(result[2])
                        print(f"[+] extranonce1      = {self.extranonce1}")
                        print(f"[+] extranonce2_size = {self.extranonce2_size}")
                    except Exception:
                        pass

            elif msg.get("id") == auth_id:
                got_auth = True
                print("\n<-- mining.authorize :")
                print(pretty_json(msg))

            elif msg.get("method") == "mining.set_extranonce":
                params = msg.get("params", [])
                print("\n<-- mining.set_extranonce :")
                print(pretty_json(msg))
                if len(params) >= 2:
                    self.extranonce1 = params[0]
                    self.extranonce2_size = int(params[1])
                    print(f"[+] extranonce1      = {self.extranonce1}")
                    print(f"[+] extranonce2_size = {self.extranonce2_size}")


# =============================
#  Décodage du job (mining.notify)
# =============================

def decode_notify(params: List[Any], extranonce1: Optional[str], extranonce2_size: Optional[int]):
    """
    Spécification Stratum V1 (job "classique") :
    params = [
      0 job_id,
      1 prevhash,
      2 coinb1,
      3 coinb2,
      4 merkle_branch,
      5 version,
      6 nbits,
      7 ntime,
      8 clean_jobs
    ]
    """
    print("\n==================== JOB (mining.notify) ====================\n")

    if len(params) < 9:
        print("[!] Format inattendu pour mining.notify :", params)
        return

    job_id = params[0]
    prevhash_le = params[1]
    coinb1 = params[2]
    coinb2 = params[3]
    merkle_branch = params[4]
    version = params[5]
    nbits = params[6]
    ntime = params[7]
    clean_jobs = params[8]

    prevhash_be = le_hex_to_be_hex(prevhash_le)

    print(f"job_id           : {job_id}")
    print(f"prevhash (LE)    : {prevhash_le}")
    print(f"prevhash (BE)    : {prevhash_be}")
    print(f"version          : {version}")
    print(f"nbits            : {nbits}")
    print(f"ntime            : {ntime}")
    print(f"clean_jobs       : {clean_jobs}\n")

    print(f"coinbase1 (len={len(coinb1)//2} octets)")
    print(f"  hex   : {coinb1[:120]}{'...' if len(coinb1) > 120 else ''}")
    print(f"  ascii : {hex_to_ascii_preview(coinb1)}\n")

    print(f"coinbase2 (len={len(coinb2)//2} octets)")
    print(f"  hex   : {coinb2[:120]}{'...' if len(coinb2) > 120 else ''}")
    print(f"  ascii : {hex_to_ascii_preview(coinb2)}\n")

    if extranonce1 is not None:
        print(f"extranonce1      : {extranonce1} (len={len(extranonce1)//2} octets)")
    else:
        print("extranonce1      : non défini")

    if extranonce2_size is not None:
        print(f"extranonce2_size : {extranonce2_size} octets\n")
    else:
        print("extranonce2_size : non défini\n")

    print(f"Merkle branch ({len(merkle_branch)} éléments) :")
    for idx, h in enumerate(merkle_branch):
        print(f"  [{idx}] {h}")
    print()

    print("Coinbase reconstruite par le mineur :")
    print("    coinbase = coinb1 + extranonce1 + extranonce2 + coinb2\n")

    # ============================
    # Reconstruction + décodage
    # ============================
    if extranonce1 is None or extranonce2_size is None:
        print("[!] Impossible de reconstruire la coinbase (extranonce1 ou extranonce2_size manquants).")
        print("\n============================================================\n")
        return

    try:
        fake_extranonce2 = "00" * extranonce2_size
        coinbase_hex = coinb1 + extranonce1 + fake_extranonce2 + coinb2
        print("[+] Coinbase (avec extranonce2 factice remplie de 00) :")
        print(f"    {coinbase_hex}\n")

        outputs = parse_tx_outputs(coinbase_hex)
        print("[+] Sorties de la transaction coinbase :")
        for idx, (value_sat, script_hex) in enumerate(outputs):
            btc = value_sat / 1e8
            addr = script_to_address(script_hex, network="main")
            print(f"  vout[{idx}] : {btc:.8f} BTC")
            print(f"    scriptPubKey : {script_hex}")
            if addr:
                print(f"    adresse      : {addr}")
            else:
                print(f"    adresse      : <type de script non géré>")
        print()
    except Exception as e:
        print(f"[!] Erreur lors du décodage de la coinbase : {e}")

    print("============================================================\n")


# =============================
#  Main
# =============================

def parse_host_port(host_arg: str, port_arg: Optional[int]) -> (str, int, bool):
    """
    Gère les formats d'adresse suivants :
      - "pool.com"
      - "pool.com:3333"
      - "stratum+tcp://pool.com:3333"
      - "stratum+ssl://pool.com:4444"
    """
    use_tls = False
    host = host_arg

    if host.startswith("stratum+tcp://"):
        host = host[len("stratum+tcp://"):]
    elif host.startswith("stratum+ssl://") or host.startswith("stratum+tls://"):
        host = host.split("://", 1)[1]
        use_tls = True

    if ":" in host:
        h, p = host.rsplit(":", 1)
        host = h
        try:
            port = int(p)
        except ValueError:
            raise ValueError(f"Port invalide dans {host_arg!r}")
    else:
        if port_arg is None:
            raise ValueError("Port absent (ni dans --host ni dans --port).")
        port = port_arg

    return host, port, use_tls


def main():
    parser = argparse.ArgumentParser(description="BlockTemplate Inspector – analyseur de jobs Stratum (mining.notify).")
    parser.add_argument("--host", required=True, help="Adresse du serveur Stratum (ex: stratum+tcp://pool.com:3333)")
    parser.add_argument("--port", type=int, help="Port Stratum si non inclus dans --host")
    parser.add_argument("--user", required=True, help="Identifiant Stratum")
    parser.add_argument("--password", default="x", help="Mot de passe Stratum (souvent 'x')")
    parser.add_argument("--timeout", type=int, default=20, help="Délai maximum des opérations réseau")

    args = parser.parse_args()

    try:
        host, port, use_tls = parse_host_port(args.host, args.port)
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        sys.exit(1)

    client = StratumClient(
        host=host,
        port=port,
        user=args.user,
        password=args.password,
        use_tls=use_tls,
        timeout=args.timeout,
    )

    try:
        client.connect()
        client.subscribe_and_authorize()

        print("\n[+] Attente du premier job (mining.notify)...\n")

        # Lecture du premier job
        while True:
            msg = client.read_message()
            if not msg:
                continue

            if msg.get("method") == "mining.notify":
                print("<-- mining.notify :")
                print(pretty_json(msg))
                decode_notify(msg.get("params", []), client.extranonce1, client.extranonce2_size)
                print("[+] Analyse du premier job terminée.")
                break

    except Exception as e:
        print(f"[ERREUR] {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if client.socket:
            client.socket.close()


if __name__ == "__main__":
    main()
