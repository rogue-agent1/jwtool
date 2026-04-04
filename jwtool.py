#!/usr/bin/env python3
"""jwtool - JWT decoder, inspector, and builder.

Decode, inspect, and create JWTs without external dependencies. Zero deps.
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
from datetime import datetime


def b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def cmd_decode(args):
    token = args.token.strip()
    parts = token.split(".")
    if len(parts) not in (2, 3):
        print("Invalid JWT format")
        sys.exit(1)

    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))

    print("Header:")
    print(json.dumps(header, indent=2))
    print("\nPayload:")
    print(json.dumps(payload, indent=2))

    # Time fields
    now = time.time()
    for field in ("exp", "iat", "nbf"):
        if field in payload:
            ts = payload[field]
            dt = datetime.fromtimestamp(ts).isoformat()
            if field == "exp":
                status = "✓ valid" if ts > now else "✗ EXPIRED"
                remaining = ts - now
                if remaining > 0:
                    print(f"\n  exp: {dt} ({status}, {int(remaining)}s remaining)")
                else:
                    print(f"\n  exp: {dt} ({status}, expired {int(-remaining)}s ago)")
            elif field == "iat":
                print(f"  iat: {dt} ({int(now - ts)}s ago)")
            elif field == "nbf":
                status = "✓ active" if ts <= now else "✗ not yet valid"
                print(f"  nbf: {dt} ({status})")

    if len(parts) == 3:
        print(f"\n  Signature: {parts[2][:20]}...")
        print(f"  Algorithm: {header.get('alg', 'none')}")


def cmd_verify(args):
    token = args.token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        print("Invalid JWT (need 3 parts)")
        sys.exit(1)

    header = json.loads(b64url_decode(parts[0]))
    alg = header.get("alg", "")
    message = f"{parts[0]}.{parts[1]}".encode()

    alg_map = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
    if alg not in alg_map:
        print(f"Unsupported algorithm: {alg} (only HS256/384/512)")
        sys.exit(1)

    expected = hmac.new(args.secret.encode(), message, alg_map[alg]).digest()
    actual = b64url_decode(parts[2])

    if hmac.compare_digest(expected, actual):
        print("✓ Signature valid")
        payload = json.loads(b64url_decode(parts[1]))
        if "exp" in payload and payload["exp"] < time.time():
            print("⚠ Token is expired")
    else:
        print("✗ Signature invalid")
        sys.exit(1)


def cmd_create(args):
    header = {"alg": args.alg or "HS256", "typ": "JWT"}
    payload = json.loads(args.payload)

    if args.exp:
        payload["exp"] = int(time.time() + parse_duration(args.exp))
    if args.iat:
        payload["iat"] = int(time.time())
    if args.sub:
        payload["sub"] = args.sub
    if args.iss:
        payload["iss"] = args.iss

    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    message = f"{h}.{p}".encode()

    alg_map = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}
    alg = header["alg"]
    if alg == "none":
        sig = ""
    elif alg in alg_map:
        sig = b64url_encode(hmac.new(args.secret.encode(), message, alg_map[alg]).digest())
    else:
        print(f"Unsupported: {alg}")
        sys.exit(1)

    print(f"{h}.{p}.{sig}")


def parse_duration(s):
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if s[-1] in units:
        return float(s[:-1]) * units[s[-1]]
    return float(s)


def cmd_claims(args):
    """Extract specific claims from JWT."""
    token = args.token.strip()
    parts = token.split(".")
    payload = json.loads(b64url_decode(parts[1]))
    for claim in args.names:
        if claim in payload:
            print(f"  {claim}: {payload[claim]}")
        else:
            print(f"  {claim}: (not present)")


def main():
    p = argparse.ArgumentParser(description="JWT toolkit")
    sub = p.add_subparsers(dest="cmd")

    dp = sub.add_parser("decode", help="Decode and inspect JWT")
    dp.add_argument("token")

    vp = sub.add_parser("verify", help="Verify JWT signature")
    vp.add_argument("token")
    vp.add_argument("secret")

    cp = sub.add_parser("create", help="Create a JWT")
    cp.add_argument("payload", help='JSON payload, e.g. \'{"sub":"user"}\'')
    cp.add_argument("secret")
    cp.add_argument("-a", "--alg", default="HS256", choices=["HS256", "HS384", "HS512", "none"])
    cp.add_argument("--exp", help="Expiry duration (e.g. 1h, 7d)")
    cp.add_argument("--iat", action="store_true", help="Add issued-at")
    cp.add_argument("--sub", help="Subject claim")
    cp.add_argument("--iss", help="Issuer claim")

    clp = sub.add_parser("claims", help="Extract specific claims")
    clp.add_argument("token")
    clp.add_argument("names", nargs="+")

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)
    {"decode": cmd_decode, "verify": cmd_verify, "create": cmd_create, "claims": cmd_claims}[args.cmd](args)


if __name__ == "__main__":
    main()
