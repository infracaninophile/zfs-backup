# zfs-backup

Backup or mirror ZFSes using zfs send and receive.

* Runs as non-root user.
* Uses passphrase-less SSH keys with a forced command for better security.
* Requires no configuration files -- all required information is
  derived from the command line or by use of custom ZFS properties.
* Requires a recent version of ZFS with bookmark support.

See the built-in help text for usage info.

