<p align="center">
  <img src="assets/logo-src.jpg" alt="STRS logo" width="220">
</p>

# SuperTransfer (STRS)

Send big files and folders straight from your PC to a friend's PC.
No cloud, no account, no upload site. You pick the files, set a password, and
your friend types that password to download them.

## How it works

1. You run STRS and choose **Send Files To A Friend**.
2. STRS shows you a short block of text (it holds your address and password).
   Send that block to your friend in any chat app.
3. Your friend runs STRS, chooses **Receive Files**, and pastes the block in.
   If they have used STRS with you before, typing just the password is enough.
4. The files go from your PC to theirs. Keep your window open until it finishes.

Your PC is the "relay" (the go-between), and STRS starts it for you. There is
nothing else to install or run.

## What you get

- **Private:** connections are encrypted, and so are the files themselves
  (see "How your files are protected" below). The block also holds a "pin", a
  fingerprint of your PC's certificate, so your friend's copy can tell it is
  really talking to your PC and not someone pretending to be it.
- **Discreet:** your friend's address and PC name are hidden. Logs and the
  sender's window show only a masked address like `90.203.x.x` and the name
  "your friend".
- **Fast:** many connections at once, and lots of small files are bundled so
  they don't slow things down.
- **Safe:** every file is checked after it arrives (using a SHA-256 hash, a
  fingerprint of its contents), so a damaged file is caught and fetched again.
- **Resumable:** if the connection drops, the download carries on where it
  stopped.
- **Tidy:** if you stop a download yourself (Ctrl-C or closing the window), the
  half-finished files are deleted.

## Download

Get the files from the [Releases page](../../releases).

| You are on | Download |
|---|---|
| Windows | `STRS.exe` |
| Linux (Arch, Ubuntu, Debian and others) | `STRS-linux` |

Your friend needs the same program on their computer.

## Windows

1. Download `STRS.exe` and double-click it.
2. Choose **1** to send or **2** to receive.

If Windows asks about the firewall, allow it. That lets your friend connect.

## Linux (Arch, Ubuntu, Debian, and others)

`STRS-linux` is a single file with no dependencies. You do not need to install
any packages. It works on 64-bit Intel/AMD Linux, including Arch, Ubuntu,
Debian, Mint, Fedora and others.

```bash
chmod +x STRS-linux
./STRS-linux
```

To use it from anywhere as `STRS`:

```bash
sudo install -m 755 STRS-linux /usr/local/bin/STRS
STRS
```

If your friend is outside your home network, your firewall must allow the
port STRS uses (8443). Only do this if you have a firewall turned on:

| Distro | Command |
|---|---|
| Ubuntu / Debian (ufw) | `sudo ufw allow 8443/tcp` |
| Arch / Fedora (firewalld) | `sudo firewall-cmd --add-port=8443/tcp` |

## Sending to someone outside your home

STRS asks your router to open a port automatically (this is called UPnP). If
your router has UPnP turned off, open **TCP port 8443** to your PC yourself in
the router settings (this is called port forwarding). Without it, only people
on your own network can connect.

## Using it from a terminal

Run `STRS` with no arguments for the menu, or use commands:

```
STRS send     set a password, pick files, share them
STRS receive  type the password, pick a folder, download
STRS scan     show what send would share, without sharing it
STRS info     show settings and paths
```

Handy options:

- `-dir PATH` folder to send (send)
- `-all` take everything without asking (send and receive)
- `-password PASS` the password your friend gave you (receive)
- `-out PATH` where to save the files (receive)
- `-fresh` ignore a half-finished download and start over (receive)
- `-streams N` number of connections (default 16)

## Running the relay on its own (optional)

Most people never need this. `supertransfer-relay` is for a Linux server that
should only host transfers and not send or receive anything itself. It is not
on the Releases page: build it with `./build.sh` (see "Build it yourself"
below). The result in `dist/` is a single static file that runs on any 64-bit
Linux.

```bash
chmod +x supertransfer-relay
./supertransfer-relay -listen :8443 -advertise your.server.address:8443
```

Options: `-streams`, `-ttl`, `-max-sessions`, `-public-port`, `-no-upnp`,
`-log FILE`.

## Build it yourself

You need [Go](https://go.dev/dl/) installed.

```bash
git clone https://github.com/Slxcky-1/SuperTransferSpeeds.git
cd SuperTransferSpeeds
./build.sh
```

The programs are written to the `dist/` folder. The build also runs the unit
tests.

## Testing

`tests/e2e.sh` runs real transfers on your own machine (Linux, macOS, WSL or
Git Bash; needs Go and Python 3). It checks that:

- a normal transfer arrives intact, and a relay never sees the password or
  readable file data
- a relay that changes data in transit is caught, even if it also forges the
  checksum
- a wrong password delivers nothing
- packs of small files, empty files and resuming a killed download all work

```bash
tests/e2e.sh
```

It uses a temporary folder and removes it afterwards. The hostile relay it
builds exists only for the test and is never part of a release.

## How your files are protected

Files are encrypted from your PC to your friend's PC, so even the relay in the
middle cannot read them or change them without being caught. This matters most
if you run the relay on a server you don't fully trust. When you send from
your own PC, the relay is your PC.

- **The password never leaves your PC.** The relay only ever gets a one-way
  code worked out from it, which is useless for decrypting anything.
- **Files are locked with AES-256**, using a different key for every file.
- **Changes are caught.** Each chunk is signed with a key only you and your
  friend can make, so a relay can't swap in data of its own.

What is **not** hidden: the relay can still see file names, file sizes, when
you transfer and your friend's address (masked in the logs). It needs these to
do its job.

The protection is only as strong as the password. Anyone who can guess it can
unlock the files, so use a long one, such as three or four random words.

## Good to know

- Version 1.1 and newer cannot talk to older versions. Both you and your
  friend need the same download.

- A password can only be used for one transfer at a time. If you see "already
  serving a transfer", close the other STRS window first.
- Passwords last 24 hours.
- Settings are saved in your user config folder, and a small config file in
  your temp folder under `STRS`.

## License

MIT. See [LICENSE](LICENSE).
