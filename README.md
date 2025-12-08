# BlockTemplate Inspector

BlockTemplate Inspector is a lightweight Stratum V1 analysis tool designed to connect to a mining pool, receive a `mining.notify` job, and display its full structure.
It provides a clear breakdown of the block template sent by a Stratum server, including the coinbase transaction components, extranonce values, merkle branches, and block header fields.

This tool is useful for developers, miners, and pool operators who want to inspect how a pool constructs block templates or verify whether a pool is independently generating them.

## Features

* Connects to any Stratum V1 endpoint (TCP or SSL).
* Sends `mining.subscribe` and `mining.authorize`.
* Captures and displays the first `mining.notify` job.
* Prints detailed information:

  * job ID
  * previous block hash (LE and BE formats)
  * version, nBits, nTime, clean_jobs flag
  * coinbase1 and coinbase2 (hex and ASCII preview)
  * extranonce1 and extranonce2 size
  * Merkle branch entries
* Shows how the miner reconstructs the coinbase transaction.
* Helps identify whether the pool builds its own block templates or acts as a proxy.

## Usage

Run the script with:

```bash
python3 blocktemplate_inspector.py \
  --host stratum+tcp://pool.example.com:3333 \
  --user worker_name \
  --password x
```

If the port is not included in the host argument:

```bash
python3 blocktemplate_inspector.py \
  --host pool.example.com \
  --port 3333 \
  --user worker_name
```

The tool will:

1. Connect to the Stratum server.
2. Subscribe and authorize.
3. Wait for the first `mining.notify`.
4. Decode and print all job details.

## Requirements

* Python 3.7 or higher
* No external dependencies (only uses Python standard library)

## Notes

* SSL support is available using the `stratum+ssl://` or `stratum+tls://` prefix.
* The script stops after decoding the first job for clarity and simplicity.
* This is an inspection tool and does not perform any mining or share submission.


## Example Output

Below is a simplified example of what the tool prints when connecting to a Stratum server and receiving the first `mining.notify` job.
All values below are placeholders and do not reflect real pool data.

```
[+] Connecting to Stratum server chauffagistes-pool.fr:3333 (TLS=False)
[+] Connection established.

--> mining.subscribe sent (id=2)
--> mining.authorize sent (id=3)

<-- mining.subscribe:
{
  "id": 2,
  "error": null,
  "result": [
    [
      ["mining.notify", "abcd1234"]
    ],
    "1a2b3c4d",
    8
  ]
}
[+] extranonce1      = 1a2b3c4d
[+] extranonce2_size = 8

<-- mining.authorize:
{
  "id": 3,
  "error": null,
  "result": true
}

[+] Waiting for first job (mining.notify)...

<-- mining.notify:
{
  "id": null,
  "method": "mining.notify",
  "params": [
    "job1234abcd",
    "00112233445566778899aabbccddeeff00000000000000000000000000000000",
    "01000000ffffffff...",
    "0a636b706f6f6c2f6d696e65642f6578616d706c65ffffffff...",
    [
      "merklehash1...",
      "merklehash2...",
      "merklehash3..."
    ],
    "20000000",
    "1701e2a0",
    "65000000",
    false
  ]
}

==================== JOB (mining.notify) ====================

job_id           : job1234abcd
prevhash (LE)    : 00112233445566778899aabbccddeeff00000000000000000000000000000000
prevhash (BE)    : 00000000000000000000000000000000ffeeddccbbaa99887766554433221100
version          : 20000000
nbits            : 1701e2a0
ntime            : 65000000
clean_jobs       : False

coinbase1 (len=40 bytes)
  hex   : 01000000ffffffff...
  ascii : .........................................@.:%....,7i...u.

coinbase2 (len=60 bytes)
  hex   : 0a636b706f6f6c2f6d696e65642f6578616d706c65ffffffff...
  ascii : .ckpool./mined by Les Chauffagistes/..................5.\}...W..VL...q.............

extranonce1      : 1a2b3c4d (len=4 bytes)
extranonce2_size : 8 bytes

Merkle branch (3 elements):
  [0] merklehash1...
  [1] merklehash2...
  [2] merklehash3...

Coinbase reconstruction:
    coinbase = coinb1 + extranonce1 + extranonce2 + coinb2

============================================================

[+] Job analysis complete.
```


## Author

[itrider-gh](https://github.com/itrider-gh)

## License

MIT License.
