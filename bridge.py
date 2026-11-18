#!/usr/bin/env python3
"""Constellation Mesh Lab radio bridge.

Serves the lab page on http://127.0.0.1:8737 and moves IQ samples between the
page and a radio. The page does all modulation, decoding and encryption; this
program only carries samples.

Backends (pick one way out and one way in):
  --loopback                 transmit straight back into receive, with noise (no radio needed)
  --udp-tx HOST:PORT         send cf32 IQ datagrams (GNU Radio UDP source, another bridge)
  --udp-rx PORT              receive cf32 IQ datagrams
  --tx-cmd "COMMAND"         pipe IQ into a program's stdin   (see --tx-format)
  --rx-cmd "COMMAND"         read IQ from a program's stdout  (see --rx-format)

Standard library only. numpy is used when installed and is required for
--decim and --rx-shift.
"""
import argparse, array, collections, http.server, json, operator, os, random, shlex, socket, subprocess, sys, threading, time, urllib.parse

try:
    import numpy as np
except Exception:  # numpy is optional
    np = None

HERE = os.path.dirname(os.path.abspath(__file__))


class Ring:
    """Received samples as interleaved float32 I/Q bytes, addressed by absolute sample number."""

    def __init__(self, rate, seconds=6.0):
        self.max = int(rate * seconds) * 8
        self.buf = bytearray()
        self.start = 0
        self.lock = threading.Lock()
        self.rec = None

    def append(self, b):
        if not b:
            return
        with self.lock:
            self.buf += b
            if self.rec:
                self.rec.write(b)
            extra = len(self.buf) - self.max
            if extra > 0:
                extra -= extra % 8
                del self.buf[:extra]
                self.start += extra // 8

    def read(self, cursor, limit):
        with self.lock:
            end = self.start + len(self.buf) // 8
            if cursor < 0 or cursor > end:
                cursor = end
            if cursor < self.start:
                cursor = self.start
            n = min(limit, end - cursor)
            o = (cursor - self.start) * 8
            return cursor, bytes(self.buf[o:o + n * 8]), cursor + n


def to_f32(data, fmt):
    """Raw bytes in fmt -> interleaved float32 bytes."""
    if fmt == 'cf32':
        return data
    if np is not None:
        if fmt == 'cu8':
            a = (np.frombuffer(data, np.uint8).astype(np.float32) - 127.5) / 127.5
        elif fmt == 'cs8':
            a = np.frombuffer(data, np.int8).astype(np.float32) / 127.0
        else:
            a = np.frombuffer(data, np.int16).astype(np.float32) / 32768.0
        return a.tobytes()
    if fmt == 'cu8':
        return array.array('f', [(v - 127.5) / 127.5 for v in data]).tobytes()
    if fmt == 'cs8':
        return array.array('f', [v / 127.0 for v in array.array('b', data)]).tobytes()
    return array.array('f', [v / 32768.0 for v in array.array('h', data)]).tobytes()


def from_f32(data, fmt):
    """Interleaved float32 bytes -> raw bytes in fmt, clipped."""
    if fmt == 'cf32':
        return data
    if np is not None:
        a = np.clip(np.frombuffer(data, np.float32), -1.0, 1.0)
        if fmt == 'cu8':
            return (a * 127.5 + 127.5).astype(np.uint8).tobytes()
        if fmt == 'cs8':
            return np.round(a * 127.0).astype(np.int8).tobytes()
        return np.round(a * 32767.0).astype(np.int16).tobytes()
    a = array.array('f', data)
    c = lambda v: max(-1.0, min(1.0, v))
    if fmt == 'cu8':
        return bytes(int(c(v) * 127.5 + 127.5) for v in a)
    if fmt == 'cs8':
        return array.array('b', [int(round(c(v) * 127.0)) for v in a]).tobytes()
    return array.array('h', [int(round(c(v) * 32767.0)) for v in a]).tobytes()


BYTES_PER_SAMPLE = {'cf32': 8, 'cu8': 2, 'cs8': 2, 'cs16': 4}


class Bridge:
    def __init__(self, a):
        self.a = a
        self.rate = a.rate
        self.ring = Ring(a.rate)
        self.txq = collections.deque()
        self.tx_sent = 0
        self.rx_phase = 0.0
        self.rx_rem = b''
        self.rx_tail = None
        self.tx_last = None
        self.procs = []
        self.udp_out = None
        if a.record:
            self.ring.rec = open(a.record, 'ab')
        if a.loopback:
            r = random.Random(1)
            self.noise = array.array('f', [r.gauss(0, a.noise) for _ in range(1 << 16)])
        if a.udp_tx:
            host, port = a.udp_tx.rsplit(':', 1)
            self.udp_out = (socket.socket(socket.AF_INET, socket.SOCK_DGRAM), (host, int(port)))
        if a.tx_cmd:
            self.tx_proc = subprocess.Popen(shlex.split(a.tx_cmd), stdin=subprocess.PIPE)
            self.procs.append(self.tx_proc)
        if a.udp_rx:
            threading.Thread(target=self.udp_in, daemon=True).start()
        if a.rx_cmd:
            self.rx_proc = subprocess.Popen(shlex.split(a.rx_cmd), stdout=subprocess.PIPE)
            self.procs.append(self.rx_proc)
            threading.Thread(target=self.pipe_in, daemon=True).start()
        threading.Thread(target=self.tx_loop, daemon=True).start()

    # ---- receive side ----
    def ingest(self, f32):
        """Radio-rate float32 bytes -> optional frequency shift and decimation -> ring."""
        a = self.a
        if a.rx_decim > 1 or a.rx_shift:
            x = np.frombuffer(self.rx_rem + f32, np.float32)
            n = (len(x) // 2 // a.rx_decim) * a.rx_decim
            self.rx_rem = x[2 * n:].tobytes()
            if not n:
                return
            z = x[0:2 * n:2] + 1j * x[1:2 * n:2]
            if a.rx_shift:
                w = 2 * np.pi * a.rx_shift / (a.rate * a.rx_decim)
                z = z * np.exp(1j * (self.rx_phase + w * np.arange(n)))
                self.rx_phase = (self.rx_phase + w * n) % (2 * np.pi)
            if a.rx_decim > 1:
                z = z.reshape(-1, a.rx_decim).mean(axis=1)
            out = np.empty(2 * len(z), np.float32)
            out[0::2] = z.real
            out[1::2] = z.imag
            f32 = out.tobytes()
        self.ring.append(f32)

    def udp_in(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('0.0.0.0', self.a.udp_rx))
        rem = b''
        while True:
            d = rem + s.recv(65536)
            n = len(d) - len(d) % 8
            rem = d[n:]
            self.ingest(d[:n])

    def pipe_in(self):
        bps = BYTES_PER_SAMPLE[self.a.rx_format]
        rem = b''
        while True:
            d = self.rx_proc.stdout.read1(1 << 16)
            if not d:
                print('bridge: the receive command ended', file=sys.stderr)
                return
            d = rem + d
            n = len(d) - len(d) % bps
            rem = d[n:]
            self.ingest(to_f32(d[:n], self.a.rx_format))

    # ---- transmit side ----
    def upsample(self, f32):
        """Page-rate float32 bytes -> radio rate by linear interpolation."""
        d = self.a.tx_decim
        if d <= 1:
            return f32
        x = np.frombuffer(f32, np.float32)
        z = x[0::2] + 1j * x[1::2]
        prev = self.tx_last if self.tx_last is not None else 0j
        zz = np.concatenate(([prev], z))
        t = np.arange(1, d + 1) / d
        y = (zz[:-1, None] * (1 - t) + zz[1:, None] * t).reshape(-1)
        self.tx_last = z[-1]
        out = np.empty(2 * len(y), np.float32)
        out[0::2] = y.real
        out[1::2] = y.imag
        return out.tobytes()

    def sink(self, f32, idle):
        a = self.a
        if a.loopback:
            s = array.array('f', f32)
            o = random.randrange(len(self.noise) - len(s))
            self.ring.append(array.array('f', map(operator.add, s, self.noise[o:o + len(s)])).tobytes())
        if idle and not a.tx_cmd:
            return
        if self.udp_out and not idle:
            sock, addr = self.udp_out
            for o in range(0, len(f32), 1472):
                sock.sendto(f32[o:o + 1472], addr)
        if a.tx_cmd:
            try:
                self.tx_proc.stdin.write(from_f32(self.upsample(f32), a.tx_format))
                self.tx_proc.stdin.flush()
            except (BrokenPipeError, ValueError):
                print('bridge: the transmit command ended', file=sys.stderr)
                a.tx_cmd = None

    def tx_loop(self):
        tick = 0.02
        n = int(self.rate * tick) * 8
        pending = bytearray()
        nxt = time.monotonic()
        zeros = bytes(n)
        while True:
            while self.txq:
                pending += self.txq.popleft()
            if pending:
                chunk = bytes(pending[:n])
                del pending[:n]
                self.tx_sent += len(chunk) // 8
                if len(chunk) < n:
                    chunk += bytes(n - len(chunk))
                self.sink(chunk, False)
            else:
                self.sink(zeros, True)
            nxt += tick
            time.sleep(max(0.0, nxt - time.monotonic()))

    def describe(self):
        a = self.a
        way_out = 'loopback' if a.loopback else 'udp ' + a.udp_tx if a.udp_tx else 'command' if a.tx_cmd else 'none'
        way_in = 'loopback' if a.loopback else 'udp port %d' % a.udp_rx if a.udp_rx else 'command' if a.rx_cmd else 'none'
        return {'ok': True, 'rate': self.rate, 'tx': way_out, 'rx': way_in, 'rx_decim': a.rx_decim, 'tx_decim': a.tx_decim, 'freq': a.freq,
                'cursor': self.ring.start + len(self.ring.buf) // 8, 'tx_sent': self.tx_sent, 'numpy': np is not None}


def make_handler(bridge):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kw):
            super().__init__(*args, directory=HERE, **kw)

        def log_message(self, *args):
            pass

        def send_bytes(self, body, ctype, extra=None):
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            if u.path == '/api/status':
                return self.send_bytes(json.dumps(bridge.describe()).encode(), 'application/json')
            if u.path == '/api/rx':
                q = urllib.parse.parse_qs(u.query)
                cursor = int(q.get('cursor', ['-1'])[0])
                start, data, nxt = bridge.ring.read(cursor, int(bridge.rate * 0.5))
                return self.send_bytes(data, 'application/octet-stream', {'X-Start': str(start), 'X-Next': str(nxt)})
            return super().do_GET()

        def do_POST(self):
            if urllib.parse.urlparse(self.path).path != '/api/tx':
                return self.send_error(404)
            n = int(self.headers.get('Content-Length', '0'))
            if n > 16 << 20:
                return self.send_error(413)
            body = self.rfile.read(n)
            body = body[:len(body) - len(body) % 8]
            bridge.txq.append(body)
            self.send_bytes(json.dumps({'queued': len(body) // 8}).encode(), 'application/json')

    return Handler


def main():
    p = argparse.ArgumentParser(description='Constellation Mesh Lab radio bridge')
    p.add_argument('--port', type=int, default=8737)
    p.add_argument('--host', default='127.0.0.1', help='address to serve on; anything other than 127.0.0.1 lets other machines transmit through this radio')
    p.add_argument('--rate', type=int, default=250000, help='sample rate the page works at, in samples per second')
    p.add_argument('--decim', type=int, default=1, help='radio runs at rate x decim (HackRF: --rate 250000 --decim 8 for 2 MS/s)')
    p.add_argument('--rx-decim', type=int, default=0, help='override --decim for the receive radio only')
    p.add_argument('--tx-decim', type=int, default=0, help='override --decim for the transmit radio only')
    p.add_argument('--rx-shift', type=float, default=0.0, help='Hz added to the received signal to cancel a known frequency offset')
    p.add_argument('--freq', type=float, default=0.0, help='centre frequency in Hz, shown on the page only')
    p.add_argument('--loopback', action='store_true')
    p.add_argument('--noise', type=float, default=0.03, help='loopback noise level')
    p.add_argument('--udp-tx')
    p.add_argument('--udp-rx', type=int)
    p.add_argument('--tx-cmd')
    p.add_argument('--tx-format', default='cs8', choices=list(BYTES_PER_SAMPLE))
    p.add_argument('--rx-cmd')
    p.add_argument('--rx-format', default='cu8', choices=list(BYTES_PER_SAMPLE))
    p.add_argument('--record', help='append every received sample to this cf32 file')
    a = p.parse_args()
    if not (a.loopback or a.udp_tx or a.udp_rx or a.tx_cmd or a.rx_cmd):
        a.loopback = True
        print('bridge: no radio given, running in loopback')
    a.rx_decim = a.rx_decim or a.decim
    a.tx_decim = a.tx_decim or a.decim
    if (a.rx_decim > 1 or a.tx_decim > 1 or a.rx_shift) and np is None:
        sys.exit('bridge: --decim and --rx-shift need numpy (pip install numpy, or apt install python3-numpy)')
    if np is None and a.rate * max(a.rx_decim, a.tx_decim) > 500000 and (a.tx_cmd or a.rx_cmd):
        print('bridge: without numpy, sample conversion may not keep up at this rate', file=sys.stderr)
    bridge = Bridge(a)
    srv = http.server.ThreadingHTTPServer((a.host, a.port), make_handler(bridge))
    print('bridge: open http://%s:%d/ in a browser  (%s)' % ('127.0.0.1' if a.host == '0.0.0.0' else a.host, a.port, json.dumps(bridge.describe())))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for pr in bridge.procs:
            pr.terminate()


if __name__ == '__main__':
    main()
