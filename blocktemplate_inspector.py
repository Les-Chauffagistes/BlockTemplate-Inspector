#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import ssl
import time
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
