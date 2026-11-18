# Constellation Mesh Lab, local bundle

To Open Go Here-------->
The Link to the LAB is: https://kenesisx.github.io/Constellation-Mesh-Lab/#signal

The lab page plus a small bridge that carries its IQ samples to and from a radio.

| File | What it is |
|---|---|
| `index.html`, `link.js` | The lab page |
| `modem.js` | Frame modem: coding, QPSK / 16-QAM, sync, decoding |
| `secure.js` | Key exchange and AES-256-GCM message encryption |
| `bridge.py` | Local web server and sample carrier (Python 3, standard library; numpy optional) |

## 1. Try it with no radio

```
python3 bridge.py --loopback
```

Open the address it prints (http://127.0.0.1:8737/). The Modem tab switches to
"Radio bridge" on its own. Everything you transmit comes straight back with
noise added, through the same path a radio would use. On the Messages tab press
"New key exchange over the air", then send messages between the two stations.

## 2. Two computers over UDP (or GNU Radio)

Computer A: `python3 bridge.py --udp-tx B_ADDRESS:9001 --udp-rx 9002`
Computer B: `python3 bridge.py --udp-tx A_ADDRESS:9002 --udp-rx 9001`

On A set "Stations on this machine" to Station 1, on B to Station 2.
The datagrams are raw complex float32 at 250 kS/s, which is what a GNU Radio
UDP source and sink use, so a flowgraph can sit between the bridge and any SDR.

## 3. Real radios through command-line tools

The bridge pipes samples into and out of any program. These command lines have
not been run on hardware by the author of this bundle; check the flags against
your installed versions.

Receive with an RTL-SDR (250 kS/s, unsigned 8-bit):

```
python3 bridge.py --rx-format cu8 \
  --rx-cmd "rtl_sdr -f 915000000 -s 250000 -g 30 -"
```

Transmit with a HackRF One (its lowest rate is 2 MS/s, so the bridge
interpolates by 8; needs numpy):

```
python3 bridge.py --tx-decim 8 --tx-format cs8 \
  --tx-cmd "hackrf_transfer -t /dev/stdin -f 915000000 -s 2000000 -x 10 -a 0"
```

Both on one station (RTL-SDR listens, HackRF talks): give both `--rx-cmd` and
`--tx-cmd` in one bridge command. Receive with a HackRF instead:
`--rx-decim 8 --rx-format cs8 --rx-cmd "hackrf_transfer -r /dev/stdout -f 915000000 -s 2000000 -l 24 -g 20"`.

Things to know:

- A HackRF One is half duplex. One HackRF cannot be both the transmit and the
  receive radio of a station at the same time.
- Frequency offset. The receiver locks to offsets up to about 1/64 of the page
  sample rate (about 3.9 kHz at 250 kS/s). Two uncalibrated radios at 915 MHz
  can differ by more. Bring them close first, read "Frequency offset found" on
  the Modem tab, and cancel it with `--rx-shift HZ` (needs numpy).
- The transmit interpolation is linear, so it leaves weak images every 250 kHz.
  Keep power low and use a band-pass filter before any amplifier.
- `--record capture.cf32` saves everything received. Drop that file on
  "Decode an IQ recording" in the Modem tab (works in the hosted page too).
- The bridge listens on 127.0.0.1 only. `--host 0.0.0.0` lets other machines
  on your network transmit through your radio.

## Rules

Encrypted messages are not allowed on amateur bands (FCC Part 97). Use an ISM
band such as 902 to 928 MHz within Part 15 power limits, and only talk to your
own stations.

## What the encryption is

- AES-256-GCM, one fresh key per message from an HMAC-SHA-256 ratchet.
- Keys agreed with ECDH (P-521 where the browser has it) and HKDF-SHA-512, or
  from a shared passphrase stretched with PBKDF2 (600,000 rounds).
- Type, sender, receiver and serial number are sent in the clear so any
  receiver can count and measure packets. They are authenticated: changing
  them makes the message fail.
- Replayed messages are rejected. Messages may arrive out of order or go
  missing without breaking later ones.
- Compare the safety number by voice to rule out someone in the middle of the
  key exchange.
- Not independently reviewed. Messages are not acknowledged or retransmitted.
