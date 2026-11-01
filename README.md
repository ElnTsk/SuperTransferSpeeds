# SuperTransfer (STRS)

SuperTransferSpeeds is a folder-to-folder file transfer tool. You pick files,
set a password, and a friend pulls them with just that password. There is no
account, no cloud storage and no upload step: your PC hosts its own relay and
the files go straight from you to them.

## Features

- **Self-hosted relay.** Sending starts a relay inside the same program. It
  asks your router (UPnP) to forward a port and hands your friend the address.
- **Password handoff.** Your friend runs `STRS`, picks **Receive Files** and
  types the password. They can also paste the whole handoff block.
- **Encrypted and pinned.** All traffic is TLS. The relay's certificate
  fingerprint (pin) is checked, so a swapped relay is refused.
- **Fast.** 16 parallel lanes by default, chunked transfers, and small files
  are packed together so thousands of tiny files cost a few round trips.
- **Verified.** Every chunk and file is checked with SHA-256 before it is
  accepted, and a receipt is written next to the files.
- **Resumable.** Interrupted downloads continue where they stopped. If you
  stop a receive yourself (Ctrl-C or closing the window), the partial files
  are deleted instead.
- **Windows and Linux.** A Windows `STRS.exe`, a Linux client, and a
  standalone relay for both.

## Quick start

1. Download `STRS.exe` from the [Releases](../../releases) page. Your friend
   needs it too.
2. Run it. Choose **1  Send Files To A Friend**, pick the files, set a
   password, and send your friend the address, pin and password it shows.
3. Your friend runs it, chooses **2  Receive Files**, and types the password.

Keep the sender window open while the transfer runs. The session ends when it
closes. A password can only serve one session at a time.

## Command line

```
STRS send     [flags]   set a password, pick files, serve them
STRS receive  [flags]   type the password, pick a drop folder, pull them
STRS scan     [flags]   show what send would offer
STRS info               show resolved server, pin cache and paths
```

Common flags: `-server host:port`, `-streams N`, `-chunk MB`.
Send: `-dir PATH`, `-all`, `-flat`, `-exclude GLOB,GLOB`, `-pack MB`.
Receive: `-password PASS`, `-from FILE`, `-out PATH`, `-all`, `-fresh`.
Run `STRS` with no arguments for the menu.

## Standalone relay

`STRS-Relay.exe` (Windows) and `supertransfer-relay` (Linux) run the relay on
its own, for a machine that only hosts:

```
supertransfer-relay -listen :8443 -advertise your.host:8443
```

Useful flags: `-streams`, `-ttl`, `-max-sessions`, `-public-port`, `-no-upnp`,
`-no-firewall`, `-log FILE`.

## Building

You need Go. From the repository root:

```
./build.sh
```

Binaries are written to `dist/`. If [`rsrc`](https://github.com/akavel/rsrc)
is installed, the Windows build also embeds the icon and manifest.

## Notes

- Your router must allow UPnP, or you must forward the TCP port yourself.
  Without a forwarded port only people on your own network can connect.
- Relay certificate and settings are kept in your user config folder, and a
  small config file in your temp folder under `STRS`.

## License

MIT. See [LICENSE](LICENSE).
