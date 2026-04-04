# jwtool

JWT decoder, inspector, verifier, and builder.

## Usage

```bash
python3 jwtool.py decode "eyJ..."                    # decode and inspect
python3 jwtool.py verify "eyJ..." "secret"           # verify signature
python3 jwtool.py create '{"sub":"user"}' "secret" --exp 1h --iat
python3 jwtool.py claims "eyJ..." sub exp role       # extract claims
```

## Features

- Decode header and payload with pretty-print
- Expiry/issued-at/not-before time analysis
- HMAC signature verification (HS256/384/512)
- JWT creation with expiry, iat, sub, iss
- Claim extraction
- Constant-time signature comparison
- Zero dependencies
