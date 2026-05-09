# Chat — End-to-End Encrypted Messenger with the Signal Protocol

A desktop chat application that implements **end-to-end encryption** following the
[Signal Protocol](https://signal.org/docs/) specification: **X3DH** (Extended
Triple Diffie–Hellman) for the asynchronous initial key agreement and the
**Double Ratchet** algorithm for the per-message symmetric ratchet.

The project is written in **Python**, ships with a **PySide6 (Qt)** graphical
client and an **aiohttp + python-socketio** relay server, and supports both
**text messages** and **encrypted file transfers**.

The server is a *dumb relay*: it stores nothing about the contents of the
conversation. All cryptographic operations — key generation, key agreement,
encryption, authentication, decryption — happen on the clients.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Repository Layout](#repository-layout)
4. [Requirements & Installation](#requirements--installation)
5. [How to Run the Application](#how-to-run-the-application)
6. [The Signal Protocol — Background](#the-signal-protocol--background)
7. [X3DH — Specification vs. This Implementation](#x3dh--specification-vs-this-implementation)
8. [The Double Ratchet — Specification vs. This Implementation](#the-double-ratchet--specification-vs-this-implementation)
9. [Symmetric Encryption Layer (AES-256-CBC + HMAC)](#symmetric-encryption-layer-aes-256-cbc--hmac)
10. [Wire Protocol — Socket.IO Events](#wire-protocol--socketio-events)
11. [Server Design](#server-design)
12. [Client / GUI Design](#client--gui-design)
13. [End-to-End Message Flow](#end-to-end-message-flow)
14. [Security Properties Achieved](#security-properties-achieved)
15. [Differences From the Official Signal Spec](#differences-from-the-official-signal-spec)
16. [Known Limitations and Possible Improvements](#known-limitations-and-possible-improvements)
17. [Credits & References](#credits--references)

---

## Project Overview

This project is an academic re-implementation of the cryptographic core of
[Signal](https://signal.org/), the protocol behind WhatsApp, Signal Messenger,
Facebook Messenger Secret Conversations, Skype Private Conversations, and many
others.

The goal is **didactic**: to write each cryptographic primitive explicitly
(key agreement, KDF chain, ratchet step, AEAD construction, message header
serialization, skipped-key buffer) instead of relying on a high-level library
such as `libsignal`. That way, every line maps directly to a step in the
Signal specification.

The result is a fully working messenger:

- two or more clients connect to a single relay server;
- the server **only forwards already-encrypted blobs** between clients;
- each pair of users derives an independent shared secret via X3DH;
- every message uses a **fresh symmetric key** thanks to the Double Ratchet;
- text messages **and arbitrary files** are end-to-end encrypted.

---

## Features

- Username-based registration with an in-memory + TinyDB key directory.
- **Identity Key (IK)**, **Signed PreKey (SPK)** and **Ed25519 signing key
  (SIK)** generated on the client.
- SPK is signed with Ed25519; the receiver verifies the signature before
  starting X3DH.
- **X3DH** initial handshake (DH1 + DH2 + DH3 → HKDF-SHA256 → 32-byte SK).
- First X3DH-protected ciphertext that doubles as a *handshake confirmation*
  (`##CHAT_START##`).
- **Double Ratchet** with:
  - DH ratchet (X25519);
  - sending / receiving symmetric chains;
  - **out-of-order delivery** support via a skipped-message-keys buffer
    (`MKSKIPPED`, capped by `MAX_SKIP = 10`);
  - per-message header `(DH, PN, N)`.
- AEAD-style construction: **AES-256-CBC** + **HMAC-SHA256** in
  *Encrypt-then-MAC* mode, with key, MAC key and IV all derived from a single
  message key via HKDF.
- **Encrypted file transfer** reusing the same Double Ratchet session.
- **PySide6** GUI: login, user list, per-peer chat window, file picker,
  out-of-order tolerant message rendering.
- **Socket.IO** transport for both client–server and (logical) peer-to-peer
  events.

---

## Repository Layout

```
Chat/
├── main.py                 # PySide6 Qt application: windows, screens, threads
├── requirements.txt        # Python dependencies
├── client/
│   ├── client.py           # Socket.IO client, User class, X3DH, dispatch
│   └── utils.py            # Crypto primitives: DH, HKDF, KDF_RK, KDF_CK,
│                           #   Header, RatchetEncrypt/Decrypt, AES+HMAC
└── server/
    ├── server.py           # aiohttp + python-socketio relay
    └── user_keys.json      # TinyDB file (public key directory)
```

`main.py` is the **entry point**. It is what you launch to use the app.
`client/` contains all the cryptography and the Socket.IO client logic.
`server/` is the relay server you must start once before any clients connect.

---

## Requirements & Installation

### Prerequisites

- **Python 3.10+** (the typing `str | None` syntax in `server.py` requires
  3.10 or later).
- A working Qt platform (Linux/macOS/Windows). On headless Linux you will
  need an X server or Wayland session for the GUI.

### Install

```bash
git clone https://github.com/FrancescoGalazzo/Chat.git
cd Chat

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

Main dependencies:

| Library | Role |
|---|---|
| `cryptography` | X25519, Ed25519, HKDF, HMAC, AES-CBC, PKCS#7 padding |
| `python-socketio` + `aiohttp` | Transport for client and server |
| `PySide6` | Qt GUI |
| `tinydb` | Lightweight JSON store for the public key directory |
| `pycryptodome` | (transitive — present in the environment) |

---

## How to Run the Application

The server listens on `http://localhost:8080`, which is also the address
hard-coded in `client/client.py` (`SERVER = 'http://localhost:8080'`).

### 1. Start the server

```bash
cd server
python server.py
```

The server **truncates** `user_keys.json` on startup
(`db.truncate()` in `server.py`), so each run begins with an empty directory.

### 2. Start one client per user (in another terminal)

```bash
python main.py
```

Type a username in the login screen. If the username is already used by an
online client, the GUI shows *"Username già in uso, scegline un altro."*
Otherwise the client is added to the directory and you land on the user list.

### 3. Chat

- Click another username on the *Select* screen → the client requests the
  peer's prekey bundle, runs **X3DH**, initialises the **Double Ratchet**, and
  opens the chat window.
- Type a message and click **Send** (encrypted text).
- Click **File** to pick any file and send it (encrypted attachment).
- **Back** returns to the user list; **Logout** disconnects.

---

## The Signal Protocol — Background

The Signal Protocol is a family of two cryptographic protocols that run
back-to-back:

1. **X3DH (Extended Triple Diffie–Hellman)** — establishes a shared secret
   `SK` between two parties even when one of them is *offline* at handshake
   time. This is achieved by publishing long-term and medium-term keys in a
   server-side *prekey bundle* and combining them with an ephemeral key on
   first contact. See the [X3DH specification](https://signal.org/docs/specifications/x3dh/).

2. **Double Ratchet** — once `SK` exists, each subsequent message uses a
   *fresh symmetric key* derived from a *root key* and *chain keys* that
   advance on every message and on every Diffie–Hellman ratchet step. See
   the [Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/).

Together they provide:

- **Forward Secrecy** — a compromise of long-term keys does not let an
  attacker decrypt past traffic.
- **Post-Compromise / Future Secrecy (Self-Healing)** — even if a session
  state leaks, future messages quickly become secure again thanks to the
  next DH ratchet step.
- **Asynchronicity** — Alice can send the first message even if Bob is
  offline.
- **Resilience to Out-of-Order delivery** — message keys are deterministic
  and skipped keys can be retained for late arrivals.

---

## X3DH — Specification vs. This Implementation

### The official X3DH

In the canonical specification, every user publishes:

| Key | Type | Lifetime |
|---|---|---|
| `IK` (Identity Key) | X25519 | long-term |
| `SPK` (Signed PreKey) | X25519, signed by `IK` | medium-term, rotated |
| `SPK_sig` | XEdDSA / Ed25519 signature | follows SPK |
| `OPK_i` (One-Time PreKeys) | X25519 | one-shot |

Alice (initiator) requests Bob's bundle, generates an ephemeral
`EK_A`, and computes:

```
DH1 = DH(IK_A, SPK_B)
DH2 = DH(EK_A, IK_B)
DH3 = DH(EK_A, SPK_B)
DH4 = DH(EK_A, OPK_B)         # only if a one-time prekey was used
SK  = HKDF(F || DH1 || DH2 || DH3 [|| DH4])
```

where `F = 0xFF * 32` (curve-specific tag) and HKDF uses an all-zero salt.

### What this project does

In `client/client.py` the same idea is implemented, but with two simplifications:

1. The user's identity key (`ik`, X25519) and the *signing* key (`sik`,
   Ed25519) are **separate** — Signal would normally use a single XEdDSA key
   for both. Here the **SPK is signed with `sik`** (Ed25519) and verified by
   the receiver before the DH steps:

   ```python
   self.sik.sign(spk_bytes)                  # producer side
   sik.verify(spk_sig_bytes, spk_bytes)      # consumer side
   ```

2. **No One-Time PreKeys are used** (`DH4` is omitted). This is allowed by
   the spec ("if no one-time prekey is available, the procedure runs without
   `DH4`") but reduces the strength of forward secrecy for the very first
   message.

The three Diffie–Hellman exchanges performed by the **initiator**
(`perform_x3dh`):

```python
dh1 = self.ik.exchange(self.sessions[username]['spk'])    # IK_A · SPK_B
dh2 = self.epk.exchange(self.sessions[username]['ik'])    # EK_A · IK_B
dh3 = self.epk.exchange(self.sessions[username]['spk'])   # EK_A · SPK_B
```

The three on the **responder** side (`receive_x3dh`):

```python
dh1 = self.spk.exchange(ika)                              # SPK_B · IK_A
dh2 = self.ik.exchange(epk)                               # IK_B  · EK_A
dh3 = self.spk.exchange(epk)                              # SPK_B · EK_A
```

The shared secret is derived with **HKDF-SHA256**, salt `0x00 * 32`, info
`b"extended_triple_diffie_hellman"`, IKM `F || DH1 || DH2 || DH3` where
`F = 0xFF * 32`:

```python
hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
            salt=b"\x00"*32, info=b"extended_triple_diffie_hellman")
SK = hkdf.derive(b"\xff"*32 + dh1 + dh2 + dh3)
```

This matches the spec exactly **except** for the missing one-time prekey
contribution.

### Associated Data

After deriving `SK`, X3DH defines an **associated data** string used for
binding the handshake:

```
AD = Encode(IK_A) || Encode(IK_B)
```

In this project `AD` is built as:

```python
ad = serialize(ik_bytes) + serialize(ik_b_bytes)   # base64 strings, concatenated
```

i.e. base64(IK_A) || base64(IK_B). It is then used as the AD input of the
authenticated encryption that protects the first message.

### Handshake confirmation message

The initiator sends a deterministic plaintext (`##CHAT_START##`) encrypted
with `SK` and bound to `AD` via HMAC. The responder uses `DECRYPT_X3DH` to
verify the MAC; if verification fails the handshake is rejected:

```python
res = DECRYPT_X3DH(SK, cipher, hmac, ad.encode('utf-8'))
if not res[0]:
    print("DH Failed"); return False
```

This serves the same purpose as Signal's *encrypted initial message* — it
proves that the responder derived the same `SK` and that the AD (and hence
the identity keys) match.

---

## The Double Ratchet — Specification vs. This Implementation

After X3DH, both sides hold the same 32-byte `SK`. They use it to
initialize the Double Ratchet, implemented in `client/utils.py`:
`RatchetEncrypt`, `RatchetDecrypt`, `DHRatchet`, `KDF_RK`, `KDF_CK`,
`SkipMessageKeys`, `TrySkippedMessageKeys`.

### Per-session state

Each direction stores the standard Double Ratchet state, exactly as in the
spec:

| Field | Meaning |
|---|---|
| `DHs` | own DH key pair (X25519) |
| `DHr` | peer's most recent DH public key |
| `RK` | root key |
| `CKs` | current sending chain key |
| `CKr` | current receiving chain key |
| `Ns` | sending message number |
| `Nr` | receiving message number |
| `PN` | number of messages in previous sending chain |
| `MKSKIPPED` | dictionary `(DHr, n) → mk` of out-of-order keys |

Initialisation:

- The **initiator** (`init_ratchet_transmission`) generates a fresh `DHs`,
  takes the responder's `SPK_B` as its initial `DHr`, and immediately runs
  one `KDF_RK(SK, DH(DHs, DHr))` step to derive the very first `CKs`.
- The **responder** (`init_ratchet_receiver`) keeps its own `SPK_B` private
  key as `DHs`, sets `DHr = None`, `RK = SK`. It will produce its own `CKs`
  the first time the peer's DH key changes.

This matches `RatchetInitAlice` / `RatchetInitBob` from the Signal
specification.

### Sending: `RatchetEncrypt`

```python
def RatchetEncrypt(state, plaintext, AD):
    state["CKs"], mk = KDF_CK(state["CKs"])
    header = HEADER(state["DHs"], state["PN"], state["Ns"])
    state["Ns"] += 1
    return header, ENCRYPT_DOUB_RATCH(mk, plaintext, CONCAT(AD, header))
```

For every outgoing message the sender:

1. advances the **chain key** `CKs` and derives a fresh **message key** `mk`
   (via `KDF_CK`);
2. builds a header containing `(DHs.pub, PN, Ns)`;
3. encrypts the plaintext under `mk` with the AEAD construction
   (`ENCRYPT_DOUB_RATCH`), using `AD || header` as associated data;
4. increments `Ns`.

### `KDF_CK` — symmetric chain step

Two HMAC-SHA256 evaluations from the same chain key with constant-byte
prefixes — exactly the construction recommended by the spec:

```
mk      = HMAC-SHA256(CK, 0x01)
next_CK = HMAC-SHA256(CK, 0x02)
```

### `KDF_RK` — root key step

`KDF_RK(rk, dh_out)` produces a new `(RK, CK)` pair using HKDF-SHA256,
output length 64:

```
HKDF(salt=rk, IKM=dh_out, info=b"kdf_rk_info") → (RK || CK)
```

### Receiving: `RatchetDecrypt`

```python
def RatchetDecrypt(state, header, ciphertext, AD):
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext is not None:
        return plaintext

    if x25519.X25519PublicKey.from_public_bytes(header.dh) != state["DHr"]:
        SkipMessageKeys(state, pn_int)
        DHRatchet(state, header)

    SkipMessageKeys(state, n_int)
    state["CKr"], mk = KDF_CK(state["CKr"])
    state["Nr"] += 1
    padded_plain = DECRYPT_DOUB_RATCH(mk, ciphertext, CONCAT(AD, header))
    return PKCS7_unpad(padded_plain)
```

It implements the standard receive logic:

1. **Try the skipped-keys buffer first.** If the incoming `(DHr, n)` matches
   a previously-stored skipped key, pop it, decrypt and return. This handles
   out-of-order delivery.
2. **DH-ratchet check.** If `header.dh` is *new*, the peer has performed a
   DH ratchet step. Skip every remaining message of the previous sending
   chain (`SkipMessageKeys(state, pn)`), then call `DHRatchet`, which:
   - bumps `PN`;
   - resets `Ns`, `Nr`;
   - sets `DHr = header.dh`;
   - derives the new receiving chain `(RK, CKr) ← KDF_RK(RK, DH(DHs, DHr))`;
   - generates a fresh local `DHs` and derives the new sending chain
     `(RK, CKs) ← KDF_RK(RK, DH(DHs, DHr))`.
3. Skip any keys before `header.n` (storing them in `MKSKIPPED`), then
   advance `CKr` once, derive `mk`, decrypt and unpad.

`MAX_SKIP = 10` caps the number of skipped keys retained between two
consecutive valid messages — a denial-of-service protection straight from
the spec (the canonical recommendation is 1000; this implementation chooses
a tighter limit).

### Header serialization

`Header` is a small wrapper that base64-encodes its three fields:

```python
{ 'dh': base64(pk_bytes), 'pn': base64(pn_int_be), 'n': base64(n_int_be) }
```

so that it can travel inside a JSON Socket.IO payload.

---

## Symmetric Encryption Layer (AES-256-CBC + HMAC)

Both X3DH (`ENCRYPT_X3DH` / `DECRYPT_X3DH`) and the Double Ratchet body
(`ENCRYPT_DOUB_RATCH` / `DECRYPT_DOUB_RATCH`) use the **same Encrypt-then-MAC
construction**, which is the construction recommended by the Double Ratchet
specification when no native AEAD is available.

### Key derivation from `mk`

Given a 32-byte symmetric key `mk` (either `SK` for X3DH or the per-message
`mk` for the ratchet), HKDF-SHA256 expands it into 80 bytes:

```python
hkdf_out = HKDF(SHA256, length=80, salt=0x00*80, info=...).derive(mk)
enc_key  = hkdf_out[:32]      # AES-256 key
auth_key = hkdf_out[32:64]    # HMAC-SHA256 key
iv       = hkdf_out[64:80]    # 16-byte AES-CBC IV
```

The `info` string differs between the two contexts (`b"X3DH"` vs.
`b"encrypt_info_kdf"`), giving domain separation between handshake
encryption and ratchet encryption.

### Encryption

```
ciphertext = AES-256-CBC( enc_key, iv, PKCS7(plaintext) )
mac        = HMAC-SHA256( auth_key, PKCS7(AD) || ciphertext )
```

Notice that the **associated data is itself PKCS#7-padded** before being
fed into HMAC. This is a project-specific detail (HMAC has no need for
fixed-block input), but it is applied symmetrically on both encrypt and
decrypt and so is consistent.

### Decryption

```
verify HMAC-SHA256( auth_key, PKCS7(AD) || ciphertext ) == mac
plaintext = unpad( AES-256-CBC^{-1}( enc_key, iv, ciphertext ) )
```

If the MAC check fails, decryption is aborted (`Exception("MAC verification
failed")` for the ratchet, `(False, "")` for X3DH).

### What `AD` looks like for ratchet messages

`AD = ad_base64(IK_A) || ad_base64(IK_B) || header.dh || header.pn || header.n`

That is, the X3DH identity-key associated data is **bound into every single
message** by being concatenated with the per-message header inside the MAC.
This guarantees that a received ciphertext belongs to *this* X3DH session
and *this* ratchet position.

---

## Wire Protocol — Socket.IO Events

Communication uses `python-socketio`. The following events are exchanged:

| Event | Direction | Purpose |
|---|---|---|
| `register_user` | C → S | Publish prekey bundle, claim a username |
| `user_joined` | S → C | Broadcast: a new user just registered |
| `user_left` | S → C | Broadcast: a user disconnected |
| `get_users` | C → S | Pull current online list |
| `request_prekey` | C → S | Fetch another user's prekey bundle |
| `x3dh_message` | C → S → C | Initiator sends EK + first ciphertext; relayed |
| `ratchet_msg` | C → S → C | Encrypted text message (ratcheted) |
| `file_msg` | C → S → C | Encrypted file (ratcheted) |
| `logout` | C → S | Voluntary disconnect |

All payloads use **base64-encoded byte strings** for keys, ciphertexts and
MACs so they can travel as JSON.

Example `ratchet_msg` payload:

```json
{
  "username": "<recipient>",
  "from":     "<sender>",
  "cipher":   "<base64>",
  "header":   { "dh": "<b64>", "pn": "<b64>", "n": "<b64>" },
  "hmac":     "<base64>"
}
```

---

## Server Design

`server/server.py` implements a minimal aiohttp + python-socketio relay:

- A single TinyDB file (`user_keys.json`) caches the public **prekey bundles**
  for online users; it is **truncated at startup**, so the directory is
  fully ephemeral.
- Two in-memory dictionaries map identities to live sockets:

  ```python
  user_map = {}   # username -> sid
  sid_map  = {}   # sid -> username
  ```

- `register_user` rejects duplicate usernames, stores the bundle,
  notifies everyone via `user_joined`, and replies with the current online
  list.
- `request_prekey` returns the public part of a peer's bundle.
- `x3dh_message`, `ratchet_msg` and `file_msg` are pure **forwarding
  events**: the server uses `sio.call(..., sid=user_map[recipient])` to push
  the encrypted blob to the recipient and return the recipient's
  acknowledgement back to the sender.
- `disconnect` removes the user from both maps and from TinyDB, then emits
  `user_left` to the rest.

The server has **no key material, no plaintext, no message log**. Even an
attacker with full server access only sees opaque ciphertexts, MACs and
public keys.

---

## Client / GUI Design

`main.py` builds the GUI with **PySide6**:

- `LoginScreen` — username entry; on submit calls `User.register_user()`.
- `SelectScreen` — one button per online peer; clicking it triggers the
  X3DH bootstrap (`request_user_prekey_bundle` + `perform_x3dh`) and
  switches to the chat window.
- `ChatScreen` — text input, **Send**, **File**, **Back**; renders the
  per-peer message history (sent in green, received in red).
- `MainWindow` — wires Qt signals from the background `Worker` thread
  (`message_received`, `user_joined`, `user_left`, `file_received`) to the
  appropriate slots. The Socket.IO event loop runs in that worker thread to
  avoid blocking the Qt event loop.

`client/client.py` defines the `User` class — the actual cryptographic
state machine — plus `reg_callback`, which registers the Socket.IO event
handlers (`x3dh_message`, `ratchet_msg`, `file_msg`, `user_joined`,
`user_left`).

When a `user_left` event arrives, `cleanup_contact` wipes the local
`messages`, `x3dh_session`, `ratchet_session` and `sessions` entries for
that peer — a small but important hygiene step.

---

## End-to-End Message Flow

A complete walk-through of *Alice* sending her first message to *Bob*:

1. **Both clients register.**
   Each generates `(IK, SIK, SPK)`, signs SPK with SIK, and pushes the
   bundle to the server with `register_user`.
2. **Alice picks Bob in the user list.**
   She fetches his bundle (`request_prekey`) and verifies `SPK_sig` with
   `IK`'s sibling Ed25519 key `SIK`.
3. **Alice runs X3DH (`perform_x3dh`).**
   She generates ephemeral `EK_A`, computes `dh1, dh2, dh3`, derives
   `SK = HKDF(0xFF*32 || dh1 || dh2 || dh3, info="extended_triple_diffie_hellman")`
   and forms `AD = b64(IK_A) || b64(IK_B)`.
4. **Alice initialises her ratchet** as the *initiator*: fresh `DHs`,
   `DHr ← SPK_B`, first `(RK, CKs) ← KDF_RK(SK, DH(DHs, SPK_B))`.
5. **Alice sends the X3DH handshake message.**
   `ENCRYPT_X3DH(SK, "##CHAT_START##", AD)` produces `(ciphertext, mac)`.
   The payload `(IK_A, EK_A, ciphertext, mac)` is forwarded via the server
   to Bob with the `x3dh_message` event.
6. **Bob receives `x3dh_message` (`receive_x3dh`).**
   He computes the *same* `dh1, dh2, dh3`, derives the *same* `SK`,
   verifies the MAC of the handshake ciphertext, and stores
   `(SK, SPK_B, AD)` in `x3dh_session`.
7. **Bob initialises his ratchet** as the *responder*: `DHs = SPK_B`,
   `RK = SK`, `DHr = None`. He has not derived any `CKs` yet — he only
   will when Alice (or he himself) performs a DH ratchet step.
8. **Alice sends a normal text message** with `RatchetEncrypt`:
   - new `mk` from `KDF_CK(CKs)`,
   - header `(DHs.pub, PN, Ns)`,
   - AES-256-CBC + HMAC over `AD || header || ciphertext`.
9. **Bob's `ratchet_msg` handler** calls `RatchetDecrypt`. Since
   `header.dh != DHr (None)` he runs `DHRatchet`, derives `CKr` (from his
   own `SPK_B`-as-`DHs` against Alice's new public key), then advances
   `CKr` once to obtain `mk`, verifies the MAC and decrypts.
10. From now on, every outgoing message advances the appropriate chain key
    (cheap), and any time one side answers with a fresh DH key the other
    performs a `DHRatchet` step (expensive but provides forward / future
    secrecy).

Files (`send_file` / `receive_file` / `decrypt_incoming_file`) follow the
*same* pipeline as text — they are simply larger plaintexts, encrypted with
the next message key from the same Double Ratchet, prefixed with the
filename in the JSON envelope.

---

## Security Properties Achieved

- **End-to-end encryption.** The server only sees `(ciphertext, mac, header)`
  blobs. There is no path inside `server.py` that touches plaintext.
- **Mutual authentication of public keys.** SPKs are verified via Ed25519
  before any DH step.
- **Forward secrecy.** Compromising any single message key does not reveal
  past or future message keys: chain keys only flow *forward* through HMAC,
  and root-key updates use ephemeral X25519 outputs that are then erased.
- **Future / Post-Compromise Secrecy.** Each new DH ratchet step injects
  fresh entropy into the root key; once a healthy ratchet step happens, an
  attacker who briefly compromised state cannot follow the conversation.
- **Replay protection.** The MAC binds the message header `(DH, PN, N)` to
  the ciphertext, and the receiver only accepts each `(DH, N)` once because
  it consumes the corresponding `mk`.
- **Out-of-order tolerance.** Up to `MAX_SKIP = 10` messages can arrive out
  of order without breaking the session.
- **Domain separation.** Different `info=` strings keep handshake-encryption
  keys, ratchet-encryption keys, root-keys and chain-keys in separate KDF
  domains.

---

## Differences From the Official Signal Spec

This implementation is **functionally faithful** to Signal but takes a few
shortcuts for clarity:

| Area | Official Signal | This project |
|---|---|---|
| Identity / signing key | One XEdDSA key (X25519 with EdDSA signing) | Two separate keys: `IK` (X25519 for DH) and `SIK` (Ed25519 for signing) |
| One-Time PreKeys (`OPK_i`) | Yes — produces `DH4` | **Not used** |
| AEAD | Typically AES-CBC + HMAC-SHA256 (matches) | AES-256-CBC + HMAC-SHA256 (matches) |
| `MAX_SKIP` | Recommended ~1000 | `10` |
| AD passed to MAC | Raw `AD || header` | `PKCS7(AD || header)` (extra padding step, harmless) |
| Prekey storage | Pluggable backend | TinyDB JSON file, truncated on startup |
| Multi-device / sender-keys / sealed sender | Supported | Not implemented |
| One-time prekey replenishment | Server-side flow | Not applicable |

---

## Known Limitations and Possible Improvements

- **No One-Time PreKeys.** Adding `OPK_i` and `DH4` would close the small
  gap in initial-message forward secrecy that exists when only `IK` and
  `SPK` are used.
- **Server is `localhost`-only.** The endpoint is hard-coded
  (`SERVER = 'http://localhost:8080'`). A small CLI/argparse switch would
  let the client target a remote server.
- **No persistent identity.** The TinyDB file is truncated on every server
  start, and identity keys are regenerated on every client launch
  (`generate_user`). A real deployment would persist them on disk
  (encrypted at rest) and pin them across sessions.
- **No transport-layer TLS.** Socket.IO traffic is plaintext over HTTP.
  Wrapping it in HTTPS/WSS is recommended even though all *application*
  payloads are already encrypted.
- **`MAX_SKIP = 10`** is conservative. Bumping it to ~1000 (as Signal does)
  is a one-line change.
- **Files travel un-chunked.** Very large files would block the Socket.IO
  event for too long; chunking + per-chunk ratcheting would scale better.
- **GUI text is mixed Italian/English.** Trivial to localise.
- **No formal unit tests.** Adding pytest cases for `KDF_CK`, `KDF_RK`,
  `RatchetEncrypt/Decrypt` round-trips, out-of-order delivery and DH-ratchet
  step would harden the codebase.

---

## Credits & References

- [Signal Protocol — X3DH specification](https://signal.org/docs/specifications/x3dh/)
  by Moxie Marlinspike and Trevor Perrin.
- [Signal Protocol — Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
  by Trevor Perrin and Moxie Marlinspike.
- [pyca/cryptography](https://cryptography.io/) — primitives (X25519,
  Ed25519, HKDF, HMAC, AES-CBC, PKCS#7).
- [python-socketio](https://python-socketio.readthedocs.io/) — transport.
- [PySide6 / Qt for Python](https://doc.qt.io/qtforpython-6/) — GUI.

> **Author.** Francesco Galazzo — Master's degree in Computer Engineering
> (Cybersecurity), Politecnico di Torino.
> Implemented as a hands-on study of the Signal Protocol's cryptographic
> core. Pull requests, comments and review of the cryptographic choices are
> very welcome.
