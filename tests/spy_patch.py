"""Turns a scratch copy of the relay into a hostile one, for tests/e2e.sh only.

Usage: spy_patch.py <path to a scratch copy of the repo>

The patched relay:
  - records the "password" the sender hands it (SPY_DIR/token.txt)
  - records the first bytes of every payload it forwards (SPY_DIR/payload.hex)
  - with SPY_MODE=flip, changes one bit of every payload
  - with SPY_MODE=forge, does that AND replaces the checksum with a matching
    one (it is given the plaintext in SPY_PLAIN, which a real relay would not
    have), to prove the signature on each chunk is what stops it

Never build this into anything you ship.
"""
import os
import sys

if len(sys.argv) != 2:
    sys.exit(__doc__)

path = os.path.join(sys.argv[1], 'internal', 'relay', 'relay.go')
src = open(path).read()


def sub(old, new):
    global src
    if src.count(old) != 1:
        sys.exit('expected exactly one match, found %d for:\n%s' % (src.count(old), old))
    src = src.replace(old, new, 1)


sub('\tpassword := strings.TrimSpace(hello.Token)\n',
    '\tpassword := strings.TrimSpace(hello.Token)\n\tspyAppend("token.txt", password)\n')

sub('\tn, err := io.CopyBuffer(c.Buf(), io.LimitReader(l.c.Raw(), length), l.buf)\n'
    '\tif err != nil {\n\t\treturn fmt.Errorf("lane_lost: splice broke: %w", err)\n\t}\n'
    '\tif n != length {\n\t\treturn fmt.Errorf("lane_lost: short splice, %d of %d bytes", n, length)\n\t}\n',
    '\tdata := make([]byte, length)\n'
    '\tif _, err := io.ReadFull(l.c.Raw(), data); err != nil {\n\t\treturn fmt.Errorf("lane_lost: splice broke: %w", err)\n\t}\n'
    '\tspyAppend("payload.hex", hex.EncodeToString(data[:min(32, len(data))]))\n'
    '\tif os.Getenv("SPY_MODE") != "spy" && len(data) > 0 {\n\t\tdata[0] ^= 0x01\n\t}\n'
    '\tif _, err := c.Buf().Write(data); err != nil {\n\t\treturn fmt.Errorf("receiver_gone: %w", err)\n\t}\n'
    '\tn := int64(len(data))\n')

sub('\tif err := c.Send(wire.Msg{T: "end", File: req.File, Index: req.Index, SHA256: end.SHA256,',
    '\tif os.Getenv("SPY_MODE") == "forge" {\n'
    '\t\tpl, _ := os.ReadFile(os.Getenv("SPY_PLAIN"))\n'
    '\t\tbad := append([]byte(nil), pl[offset:offset+length]...)\n'
    '\t\tbad[0] ^= 0x01\n'
    '\t\tsum := sha256.Sum256(bad)\n'
    '\t\tend.SHA256 = hex.EncodeToString(sum[:])\n'
    '\t}\n'
    '\tif err := c.Send(wire.Msg{T: "end", File: req.File, Index: req.Index, SHA256: end.SHA256,')

src += '''
func spyAppend(name, text string) {
	dir := os.Getenv("SPY_DIR")
	if dir == "" {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	f, err := os.OpenFile(dir+"/"+name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(text + "\\n")
}
'''
open(path, 'w').write(src)
print('spy relay patched')
