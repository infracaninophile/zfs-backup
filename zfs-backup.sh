#!/bin/sh

export PATH="/sbin:/usr/sbin:/usr/local/sbin:/bin:/usr/bin:/usr/local/sbin"

: ${BACKUPROOT:=/backup}
readonly ME=$(basename $0)
readonly COMMAND=$0
readonly enable_prop='zfs-backup:enabled'
ON_CLIENT=
ACTION=

usage( ) {
	cat >&2 <<EOF
${ME}: Usage:
    $ME __client
    $ME __list_tags [-d] -F filesystem
    $ME __list_fs [-d]
    $ME backup [-dnvz] -h hostname -u user [-f filesystem:...] [-e filesystem:...]
    $ME check [-dvz] -h hostname -u user [-f filesystem:...] [-e filesystem:...]
    $ME full [-dnvz] -h hostname -u user [-f filesystem:...] [-e filesystem:...]
    $ME list [-dvz] [-h hostname] [-f filesystem:...] [-e filesystem:...]
    $ME nuke [-dnv] -h hostname -u user [-f filesystem:...] [-e filesystem:...]
    $ME ping -h hostname -u user
    $ME setup [-d] -h hostname -u user -f filesystem:... [-e filesystem:...]

'$ME __client' For internal use: should only be run as a forced
command from the backup user's authorized_keys file.  It takes no
options.

'$ME __list_tags' For internal use on the client only.  List the tags
for all the backups known for the given filesystem, in date order,
newest first.

'$ME __list_fs' For internal use on the client only.  List all the
mounted filesystems of type ZFS which have been tagged with the
property '${enable_prop}=yes'.

'$ME ping' Test SSH connectivity and that authorized_keys has been set
up correctly on the client.

'$ME backup' sends the incremental changes between the previous backup
and now as an incremental zfs-send stream.  This has actions both
client- and server-side.  On the client it creates a snapshot, which
is only retained until the following backup completes.  The snapshot
is copied over to the server by the backup process: hence the server
will contain the history of previous backups as a series of snapshots.
Unless a filesystem is given explicitly on the command line, this
defaults tooperating on all filesystems with the property
'${enable_prop}' set to 'yes'.

'$ME check' reports on the settings both server and client side,
including the necessary SSH keys having connectivity, permissions
applied to the backup user by zfs-allow and that there is an initial
full copy of the filesystem on the backup server.  ie. the systems are
correctly set up for backup.

'$ME full' does the initial send of the full filesystem from the
client to the backup server.  This is necessary one time for the
initial setup, but subsequent use should be avoided as trying to
overwrite an existing ZFS will fail.

'$ME list' lists the snapshots available on the backup server,
optionally limiting the output to what is available a specific host or
a specific host and filesystem.

'$ME nuke' Deletes all backups for the given filesystem of the named
host.  Deletes all backup related snapshots or bookmarks for that
filesystem on the client.  There is no way to undo the effects of this
command, so don't do it unless you really mean it.

'$ME setup' Prints out shell scripts to create the filesystems needed
server-side, set up ZFS actions allowed to users necessary for the
backup to run (on both client and server) and ensures SSH authorized
keys are set up correctly.  The scripts will need to be run by root as
directed on each server.

Options:
    -d Debug mode: trace program execution to stderr.
    -e Filesystems not to backup - as a colon separated list.  Can be
       given multiple times.  Any additional exceptions will be added
       to the list.
    -f Filesystems to backup - as a colon separated list of the full
       paths from the root directory eg. /usr/local/export:/home May
       be given multiple times.  Any additional filesystems will be
       added to the list.
    -h Hostname to backup.
    -n Dry-run mode:  Show what would be done, without committing
       any changes.
    -u Username on remote host.
    -v Verbose operation: print information about progress to stderr.
    -z Compress data over the wire.  Enables SSH's Compression option.

Data are compressed on the target drive, and the usage numbers zfs
reports are by default in terms of the actual number of disk blocks
consumed.  This may be significantly less than the apparent size of
the data transferred.

Compressing SSH traffic may or may not improve performance: you will
have to experiment to find the best setting.  In general, compression
only helps on relatively low bandwidth, high RTT connections, and
where content is intrinsically compressible.

Other than the 'list' verb, always run the script on the server as the
same user, who is assumed to own the SSH key used for access and who
has write access to the per-host storage.

ToDo:

  - record the original properties of the backed up ZFSes (dump to a
    file at the mountpoint of the zfs before backup?)

EOF
	exit 1
}

# $BACKUPKEY allows password-less access to the backup user account on
# the client machine.  For security reasons, the key should be set up
# to run 'zfs-backup.sh __client' as a forced command: this will
# enforce running only the commands known to zfs-backup.sh
: ${BACKUPKEY:=$( eval echo ~$SERVERUSER)/.ssh/zfs-backup}
on_client() {
    local clienthost=$1
    local clientuser=$2
    shift 2

    if [ -n "$option_z" ]; then
        compression_opt='yes'
    else
	compression_opt='no'
    fi
        
    ssh -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityFile=$BACKUPKEY \
	-o Compression=$compression_opt $clientuser@$clienthost $COMMAND \
	${1+$@} || exit 1
}

# Echo the command line to stderr if in verbose mode, then run the
# command
runv() {
    if [ -n $option_v ]; then
	if [ "$ON_CLIENT" = 'yes' ]; then
	    echo >&2 "--> $@"
	else
	    echo >&2 "==> $@"
	fi
    fi
    "$@"
}

# The local zpool -- assumed to be the *biggest* one returned in the
# list if there are more than one.  Set ZPOOL in the environment to
# override.
get_zpool() {

    # Bah! zpool(8) doesn't have -s or -S options like zfs(8)
    zpool list -Hp -o size,name | sort -rn | head -1 | cut -f 2
}
: ${ZPOOL:=$(get_zpool)}

# Translate a filesystem path (which can contain all sorts of nasty
# stuff) into a sanitized name we can use for a ZFS.
#
# Note: According to the docs, a ZFS name can only consist of
# characters from
#   [:alnum:] _ : . -
# but a filename can contain anything except / and \0.  However we
# assume that people aren't using \n in filenames, so we can use that
# as the list separator.
#
# TODO: This is not guarranteed to generate a unique result, and
# failure to do so will end badly.
zfs_name() {
    local filesystem="$1"

    echo $filesystem | tr -c '[:alnum:]_:.-\n' _
}

# Generate the name of the ZFS used to store the backups server-side
# given the host and filesystem.
server_local_storage() {
    local var_return=$1
    local clienthost=$2
    local filesystem=$3
    local path
    
    # Without a hostname, the filesytem part is useless and will be
    # ignored.

    if [ -n "$clienthost" ]; then
	path="/$clienthost"

	if [ -n "$filesystem" ]; then
	    path="$path/$( zfs_name $filesystem )"
	fi
    fi
    
    setvar "$var_return" "$ZPOOL$BACKUPROOT$path"
}


# Identify which ZFS is mounted containing the path of interest (not
# limited to ZFS mountpoints).  Typically this is only done
# client-side.  We make up our own ZFS devices and mountpoints
# server-side, which should be mostly invisible to users.
path_to_zfs() {
    local path=$1

    zfs list -H -t filesystem -o name $path
}


# Find where the named zfs is mounted. Only returns the mountpoint, so
# not actually the inverse of path_to_zfs().
zfs_to_path() {
    local zfs=$1

    zfs list -H -t filesystem -o mountpoint $zfs
}

# snapname is used for both snapshots and bookmarks -- it is a unique
# identifier formed using 16 random hex digits.  The unique ID allows
# us to identify equivalent snapshot data between client and server
# sides -- where filesystem layouts will be quite different in
# general.
#
# We're constrained by not making the total pathname for the mounted
# snapshot too long, otherwise the .zfs/snapshot/ automount feature
# will not work and subsequently various other ZFS operations (umount,
# rename) return EBUSY. (Needs a 'zfs umount -f' to fix).
#
# 8 bytes of randomness => 16 hex digits = 2^64 = 18446744073709551616
# different possibilities, which should be enough that we just don't
# need to worry about collisions.
generate_snapname() {
    openssl rand -hex 8
}

# A regex to match the snapshot format.
readonly snap_match='[[:xdigit:]]{16}$'

# Extract the $tag from a fully or partially qualified snapshot or
# bookmark name (eg zpool/some/zfs@snapname @snapname
# zpool/some/zfs#bookmark #bookmark)
get_tag_from() {
    local name=$1

    echo ${name##*[@#]}
}


# return the list of full snapshot names matching the specified tag
get_snapshot_by_tag() {
    local zfs=$1
    local tag=$2

    zfs list -H -r -t snapshot -o name $zfs | grep -E "@$tag\$"
}

# Create a snapshot
create_snapshot() {
    local zfs=$1
    local snapname=$2

    if [ -z $option_n ]; then
	runv zfs snapshot "$zfs@$snapname"
    fi
}

# When we delete a snapshot, always create a matching bookmark
# instead. This means we can delete all backup related snapshots
# locally on the client, but still use the associated bookmark for
# incremental backups to the backup server.  Bookmarks require tiny
# amounts of space to store, so just leave them in place on the client
# indefinitely.
delete_snapshot() {
    local zfs=$1
    local snapname=$2
    
    if [ -z $option_n ]; then
	runv zfs bookmark "$zfs@$snapname" "$zfs#$snapname"
    fi

    runv zfs destroy $option_n $option_v "$zfs@$snapname"
}


# All the zfs-backup related snapshots for a specific ZFS -- the
# filesystem will differ depending on whether we're on the client or
# the server.
get_snapshots() {
    local zfs=$1
    local reversed=$2
    local sort_order

    if [ -z "$reversed" ]; then
	sort_order='-s creation' # Oldest first
    else
	sort_order='-S creation' # Reversed: newest first
    fi
    
    zfs list -H -t snapshot $sort_order -o name -r $zfs | \
	grep -E "@$snap_match"
}

# All the zfs-backup related bookmarks for a zpecific ZFS -- the
# filesystem would differ depending on whether we were on the client
# or the server, but bookmarks should only exist on the client.
get_bookmarks() {
    local zfs=$1
    local reversed=$2
    local sort_order

    if [ -z "$reversed" ]; then
	sort_order='-s creation' # Oldest first
    else
	sort_order='-S creation' # Reversed: newest first
    fi
    
    zfs list -H -t bookmark $sort_order -o name -r $zfs | \
	grep -E "#$snap_match" 
}

# List the tags for all the backups (snapshots) known
# on the named filesystem, *newest* first.
list_tags() {
    local filesystem="${1:?\"${ME}: Need a filesystem to list backup tags for\"}"
    local snapshots
    local zfs

    zfs=$( path_to_zfs $filesystem )
    : ${zfs:?"${ME}: Can't find a ZFS mounted as filesystem \"$filesystem\""}

    snapshots=$( get_snapshots $zfs 'reversed' )
    
    for snap in $snapshots; do
	get_tag_from $snap
    done
}

# Read new-line separated list of filesystems and grep out everything
# also listed in the colon separated list $exclude.
exclude_fs() {
    local exclude="$1"
    local IFS=
    
    local re="^($( echo $exclude | tr ':' '|' ))\$"

    # A pure-shellish way of achieving the same sort of result:
    # Could be slow...
    
    #for f in $ff ; do
    #	for e in $ee ; do
    #        if [ "$e" = "$f" ]; then
    #		continue 2
    #        fi
    #	done
    #	
    #	echo $f
    #done
    
    grep -vE "$re"
}

# List of filesystems for backing up, one per line.  These are the
# mounted filesytems tagged with the property 'zfs-backup:enable=yes'
client_list_fs() {
    zfs list -H -r -o ${enable_prop},mounted,mountpoint zroot | \
	awk -F \t '{ if($1 == "yes" && $2 == "yes") print $3 }' | \
	paste -s -d : -
}

# List of the filesystems currently on the server for a particular host,
# excluding those on the exclusion list.
server_list_fs() {
    local clienthost=$1
    local exclude="$2"

    local storage
    local filesystems
    
    server_local_storage storage $clienthost
    zfs list -H -d 1 -o name $storage | exclude_fs $exclude
}


# Generate the working set of filesystems: all of the filesystems
# given as -f arguments, or else all of the filesystems on the client
# with the $enable_prop set, excluding any filesystems given as -e
# arguments.
#
# Returns a list of filesystems, one per line.
client_filesystems() {
    local clienthost=$1
    local clientuser=$2
    local fslist="$3"
    local exclude="$4"
    
    # ??? Change all the server_foo() functions to read the fslist on
    # ??? stdin

    # Set the list of filesystems to backup automatically, based on
    # properties set on the client machine.
    
    if [ -z $fslist ]; then
	fslist="$( on_client $clienthost $clientuser __list_fs $option_d )"
    fi

    # Convert : separated list to space separated list.
    local IFS=:
    for fs in $fslist ; do
	echo $fs
    done | exclude_fs "$exclude"
}

# Test SSH connectvity - server pings, and client pongs in reply.
server_ping() {
    local clienthost=${1:?"Need a hostname to check connectivity to"}
    local clientuser=${2:?"Need a username to check connectivity as"}
    local response

    response=$( on_client $clienthost $clientuser ping )
    if [ "$response" != "Pong" ]; then
	echo >&2 "$ME: ERROR SSH connectivity test failed"
	return 1
    else
	echo >&2 "--> OK: SSH connectivity to $clienthost as $clientuser" \
		 "is set up correctly."
    fi
}

client_pong() {
    echo "Pong"
}


# Check that the server user can write to /$BACKUPROOT/$clienthost/ --
# this is necessary so that the user can create the mount point for
# mounting the backed-up filesystem.  Either owner or group writable
# should suffice.
check_access() {
    local serveruser=$1
    local mountpoint=$2
    local owner
    local group
    local perms
    local backupgroups
    
    owner=$(stat -f '%Su' $mountpoint)
    perms=$(stat -f '%SHp' $mountpoint)

    if [ $owner = $serveruser ]; then
	case $perms in
	    ?w?)
		echo >&2 "==> OK: \"$mountpoint\" owned and writable by $owner"
		return 0
		;;
	    *)
		echo >&2 "${ME}: FAIL \"$mountpoint\" is owned but not" \
			 "writable by $owner"
		return 1
		;;
	esac
    fi

    group=$(stat -f '%Sg' $mountpoint)
    perms=$(stat -f '%SMp' $mountpoint)
    backupgroups=$(id -Gn $serveruser)

    for bgrp in $backupgroups; do
	if [ $group = $bgrp ]; then
	    case $perms in
		?w?)
		    echo >&2 "==> OK: \"$mountpoint\" is writable by group" \
			     "$group which $user belongs to"
		    return 0
		    ;;
		*)
		    echo >&2 "${ME}: FAIL \"$mountpoint\" has negative" \
			     "permissions for group $group which $user is a" \
			     "member of"
		    return 1
		    ;;
	    esac
	fi
    done

    # If we've got to here, either $mountpoint is world writable, or
    # $serveruser has no write permissions.  Neither of which is
    # acceptable.

    echo >&2 "${ME}: FAIL \"$mountpoint\" is neither owned and writable" \
	     "by $serveruser, nor does $serveruser belong to a group" \
	     "with write permissions on it."

    return 1
}


# Check zfs has appropriate actions allowed to user for server-side use
check_zfs_server_actions() {
    local zfs=$1
    local serveruser=$2
    
    local allow
    local allowedflags=0

    allow=$( zfs allow $zfs | grep "user $serveruser" | \
	sed -e 's/^.* //' | tr ',\n' ' ' )

    for a in $allow ; do
	case $a in
	    create)
		allowedflags=$(($allowedflags + 1))
		;;
	    destroy)
		allowedflags=$(($allowedflags + 10))
		;;
	    mount)
		allowedflags=$(($allowedflags + 100))
		;;
	    receive)
		allowedflags=$(($allowedflags + 1000))
		;;
	    snapshot)
		allowedflags=$(($allowedflags + 10000))
		;;
	    *)			# Extra actions -- warning
		echo >&2 "$ME: Notice: extra action \"$a\" allowed" \
			 "to $serveruser on $zfs"
		;;
	esac
    done

    if [ $allowedflags -ne 11111 ]; then
	echo >&2 "$ME: FAIL Missing one or more required ZFS" \
	    "actions from \"create,destroy,mount,receive,snapshot\"" \
	    "for $serveruser on $zfs"
	return 1
    fi

    echo >&2 "==> OK: user $serveruser is allowed ZFS actions \"$allow\"" \
	    "on $zfs"
}    


# Check for the existence of the local filesystem that backups will be
# written to, that it has the correct option settings and that it has
# the correct ZFS actions allowed for the backup user.
check_server_setup_for_client() {
    local clienthost=$1
    local serveruser=$2
    local zfs
    local mountpoint

    server_local_storage zfs "$clienthost"
    mountpoint=$( zfs_to_path $zfs )
    if [ -z $mountpoint ]; then
	echo >&2 "$ME: FAIL Backup filesystem \"$mountpoint\" not mounted"
	return 1
    else
	echo >&2 "==> OK: backup storage \"$mountpoint\" exists"
    fi

    check_zfs_server_actions $zfs $serveruser
    
    check_access $serveruser $mountpoint
    
    return 0
}

# The specific zfs for holding this client+filesystem backups -- will
# not exist before a 'full' is run (which is OK).  If it exists, test
# that the allowed ZFS actions are appropriate and that it has
# snapshots with names in the expected pattern: ie. that it is in use
# for backups.
check_server_setup_for_filesystem() {
    local clienthost=$1
    local serveruser=$2
    local filesystem=$3		# what's backed up on the client

    local zfs
    local zfs_state
    local mountpoint		# where it's backed up on the server
    
    server_local_storage zfs $clienthost $filesystem

    # Does the ZFS exist at all?
    zfs_state=$( zfs list -H -o name -t filesystem $zfs 2>/dev/null )
    if [ -z $zfs_state ]; then
	echo >&2 "==> OK: Ready for initial full backup"
	return 0
    fi

    mountpoint=$( zfs_to_path $zfs )
    echo >&2 "==> OK: zfs $zfs exists and is mounted as $mountpoint"

    # The ZFS exists -- so is it setup for use for backups?  Check for
    # existence of snapshots matching our naming convention
    zfs_state=$( get_snapshots $zfs )
    if [ -z "$zfs_state" ]; then
	echo >&2 "==> FAIL: zfs $zfs exists but does not contain any" \
		 "previous full or incremental backup."
	echo >&2 "==> FAIL: zfs would be overwritten by backups." \
		 "Please move it out of the way."
	return 1
    fi

    # It's being used for backups.  Does it have the correct ZFS
    # allowed actions settings?  Ideally, these should be inherited
    # from the parent ZFS, but we don't check for that.

    check_zfs_server_actions $zfs $serveruser
}

# Check settings -- require the $BACKUPROOT/$clienthost zfs to exist
# and have the right allowed actions to be inherited by backed-up
# filesystems. Also require $BACKUPROOT/$clienthost to be mounted
# read/write by the current user (assumed to be the local userid that
# will run backups) -- specifically not root.
#
# Test for the existence of the filesystem dependent child zfs -- warn
# about needing to do a 'full' if this doesn't exist, otherwise list
# pre-existing backups.
#
# Test for ssh based connectivity to the client and that the
# filesystem on the client has the necessary actions allowed to the
# backup user.
server_check() {
    local clienthost=${1:?"${ME}: Need a hostname to backup"}
    local clientuser=${2:?"${ME}: Need a username to run as on the client"}
    local fslist="${3:?\"${ME}: Need a list of filesystems to backup\"}"
    local filesystem

    echo >&2 "==> Checking SERVER:"

    check_server_setup_for_client $clienthost $SERVERUSER

    for fs in $fslist ; do
	check_server_setup_for_filesystem $clienthost $SERVERUSER $filesystem
    done

    echo >&2 "--> Checking CLIENT $clienthost:"

    server_ping "$option_h" "$option_u" || return 1 

    for filesystem in $fslist ; do
	on_client $clienthost $clientuser check \
		  $option_d $option_v -u $clientuser -F $filesystem
    done
}

# Print out what needs to be done as preparation for backing up a new
# filesystem on a client machine by setting the required allowed
# actions.  Needs to be run as root on the client.
generate_setup() {
    local clienthost=${1:?"Need a client hostname to backup"}
    local clientuser=${2:?"Need a user to run the backups as on $clienthost"} 
    local fslist="${3:?\"Need a list of filesystems to backup on $clienthost\"}"

    local fs
    local zfs
    local backupserverip
    local zfs_backup_pubkey
    local scriptheader

    readonly dashes='----------------------------------------------------------------'
    
    cat >&2 <<EOF
$ME:
     Save the following commands to a file and run them as root on
     this (ie the backup) server.  Check carefully that these commands
     do what you expect and make sense.

$dashes
EOF

    # Script header 
    scriptheader='#!/bin/sh -e
'

    # Test for the existence of the BACKUP key; generate it if needed.
    if [ ! -f ${BACKUPKEY} ]; then
	cat <<EOF
$scriptheader
# Generate SSH key to use for backups.  This key needs to be owned by
# and stored under the home directory of the user -- $SERVERUSER --
# who will run the backups.  If should not have a a passphrase. It
# should only be used for this backup script.  We suggest the ed25519 key
# type for speed, but you can substitute any of the available types.

ssh-keygen -t ed25519 -N '' -C $ME -f $BACKUPKEY
chown $SERVERUSER $BACKUPKEY

EOF
	scriptheader=
    fi
    
    # Create the top-level ${ZPOOL}/backup zfs if needed.  This mostly
    # exists to inherit stuff from.  Set some default properties that
    # everything else will inherit.
    server_local_storage zfs
    if ! zfs list -H -t filesystem $zfs >/dev/null 2>&1 ; then
	cat <<EOF
$scriptheader

# Create the top level ZFS -- all storage for backed-up hosts will be
# children of this, and all backups will be grandchidren.  This will
# not store any data itself and need not be mounted: it exists only so
# that the other ZFSes can inherit properties from it.
#
# Note 1: We're using the sha256 checksum rather than the default
# fletcher4 checksum so that we can send deduplicated streams reliably
# (having multiple copies of backups in different locations is
# generally a good idea).  It is also advisable if dedup is enabled on
# the ZFS in general.
#
# Note 2: Speaking of enabling dedup: this has significant memory
# requirements and tends to slow machines to a crawl.  Don't enable
# unless you have huge quantities of ram.
#
# Note 3: Assuming these ZFSes are used in a typical backup pattern:
# ie. regular potentially large writes with only occasional need to
# read the data back, then there's no point caching any of the data in
# ARC or L2ARC.  Indeed, the volumes of data involved in backups can
# cause significant memory pressure on the backup server.  So set the
# primary and secondary cache strategies to 'metadata' only.

zfs create -o compression=lz4 -o atime=off -o exec=off -o setuid=off \\
    -o canmount=off -o dedup=off -o checksum=sha256 \\
    -o primarycache=metadata -o secondarycache=metadata \\
    -o mountpoint=${BACKUPROOT} ${zfs}

EOF
	scriptheader=
    fi

    # Create the per-host zfs and make it writable by the server backup user
    server_local_storage zfs $clienthost
    if ! zfs list -H -t filesystem $zfs >/dev/null 2>&1 ; then
	cat <<EOF
$scriptheader

# Create the per-host ZFS for $clienthost -- this should be mounted
# and read-write by the user the backups run as server-side and
# preferably not accessible by any other user account.

zfs create -o canmount=on ${zfs}
chown $SERVERUSER ${BACKUPROOT}/$clienthost
chmod 0700 ${BACKUPROOT}/$clienthost

EOF
	scriptheader=
    fi

    # Check that the backup user is allowed the required actions on
    # ${ZPOOL}/backup/$clienthost and add them if necessary 
    if ! check_zfs_server_actions $zfs $SERVERUSER >/dev/null 2>&1 ; then
	cat <<EOF
$scriptheader
# Allow the required actions 'create,destroy,mount,receive,snapshot'
# for the backup user $SERVERUSER to be able to receive snapshots and
# generally manage the local storage

zfs allow $SERVERUSER create,destroy,mount,receive,snapshot $zfs

EOF
	scriptheader=
    fi
    
    echo >&2 $dashes

    ### Client-side setup

    if [ ! -f ${BACKUPKEY} ]; then
	cat >&2 <<EOF
${ME}:
       Please generate the ssh key ${BACKUPKEY}
       as shown above, and then rerun this command to get the actions
       to setup a client machine.

$dashes
EOF
	return 0
    fi
    
    zfs_backup_pubkey=$( cat ${BACKUPKEY}.pub ) 

    # This is a gross hack.  Return the IP of the interface that has
    # had most outgoing trafic.  No guarantees that this is anything
    # like correct.
    backupserverip=$( ( netstat -i -n -f inet ; netstat -i -n -f inet6 ) | \
			  sort -rn -k 8 | head -1 | cut -w -f 4)

    cat >&2 <<EOF
$ME:
     Save the following commands to a file and run them as root on

     $clienthost

     Check this script carefully as we cannot guarantee it will be
     correct. You may need to adapt it if you are not using the usual
     layout for SSH related files, and you may need to correct the IP
     number autodetected for the backup server.

$dashes
EOF

    cat <<EOF
#!/bin/sh -e

# SSH authorized_keys. Create directory if necessary

: \${SSH_DIR:=~${clientuser}/.ssh}
if [ ! -d \$SSH_DIR ]; then
    mkdir -m 700 -p \$SSH_DIR
fi

# Backup any existing authorized_keys file

: \${AUTHORIZED_KEYS:=\$SSH_DIR/authorized_keys}
if [ -f \$AUTHORIZED_KEYS ]; then
    cp -p \$AUTHORIZED_KEYS \${AUTHORIZED_KEYS}.bak
fi

# Add the zfs-backup public key, with needed constraints NOTE: verify
# that the IP number here corresponds to what your backup server would
# use to connect to the client

if ! grep -qF $COMMAND \${AUTHORIZED_KEYS}; then
    echo "from=\"$backupserverip\",command=\"$COMMAND __client\",no-agent-forwarding,no-pty,no-X11-forwarding,no-port-forwarding $zfs_backup_pubkey" >> \$AUTHORIZED_KEYS
    chown -R ${clientuser} \$SSH_DIR
fi

# Set allowed actions on the ZFSes to be backed-up
#
# Note: the ${enable_prop} property will be inherited by all child
# ZFSes of those listed here (in the usual way that ZFS properties are
# inherited).  To backup a whole hierarchy of ZFSes you only need to
# mark the top level ZFS.  To omit some ZFSes from such a hierarchy
# set the property as ${enable_prop}=no for them.
 
IFS=: 
for fs in $fslist ; do
    : \${ZFS:=\$(zfs list -H -t filesystem -o name \$fs)}
    zfs allow $clientuser bookmark,destroy,mount,send,snapshot \$ZFS

    # Mark the ZFS as being backed-up by this script
    zfs set ${enable_prop}=yes \$ZFS 
done

EOF
    echo $dashes 2>&1
}

# Check for correct allowed actions on the client filesystem to be
# backed-up
client_check() {
    local clientuser=${1:?"${ME}: Need a username to run backups as"}
    local filesystem=${2:?"${ME}: Need a filesystem to be backed up"}
    local zfs
    local mp
    local allow
    local allowedflags=0

    zfs=$( path_to_zfs $filesystem )
    if [ -z "$zfs" ]; then
	echo >&2 "$ME: FAIL filesystem \"$filesystem\" non-existent"
	exit 1
    else
	mp=$( zfs list -o mountpoint -H $zfs )

	if [ $mp != $filesystem ]; then
	    echo >&2 "${ME}: FAIL filesystem \"$filesystem\" is not a" \
		     "mount point"
	    exit 1
	else
	    echo >&2 "--> OK: client filesystem \"$filesystem\" exists"
	fi
    fi

    allow=$( zfs allow $zfs | grep "user $clientuser" | \
		   sed -e 's/^.* //' | tr ',\n' ' ' )

    for a in $allow ; do
	case $a in
	    bookmark)
		allowedflags=$(($allowedflags + 1))
		;;
	    destroy)
		allowedflags=$(($allowedflags + 10))
		;;
	    mount)
		allowedflags=$(($allowedflags + 100))
		;;
	    send)
		allowedflags=$(($allowedflags + 1000))
		;;
	    snapshot)
		allowedflags=$(($allowedflags + 10000))
		;;
	    *)			# Extra allowed ZFS actions...
		echo >&2 "$ME: Warning: extra ZFS action \"$a\" allowed" \
			 "to $clientuser on $zfs"
		;;
	esac
    done

    if [ $allowedflags -ne 11111 ]; then
	echo >&2 "$ME: FAIL Missing required allowed ZFS actions for" \
		 "$clientuser on $zfs"
	exit 1
    fi

    echo >&2 "--> OK: user $clientuser is allowed ZFS actions \"$allow\"" \
	     "on $zfs"
    return 0
}

# On the client: send a snapshot of a filesystem to the backup server.
# If the send doesn't succeed, destroy the snapshot.
send_snapshot() {
    local zfs=$1
    local previous_snapshot=$2
    local this_snapshot=$3

    if [ -z $option_n ]; then
	runv zfs send -i $previous_snapshot "$zfs@$this_snapshot" || \
	    runv zfs destroy "$zfs@$this_snapshot"
    fi
}

# Initial backup -- send the whole filesystem snapshot to the backup
# server This should only ever happen one time, otherwise it will wipe
# out the snapshot history on the backup server.  If the send doesn't
# succeed, destroy the snapshot.
send_zfs() {
    local zfs=$1
    local snapname=$2

    runv zfs send $option_n $option_v "$zfs@$snapname" || \
	runv zfs destroy "$zfs@$snapname"
}

# (on the backup server) Receive a filesystem or an incremental update
# stream -- stored in a tree beneath /$BACKUPROOT/$hostname/
#
# If we're receiving a filesystem, this creates
# $ZPOOL$BACKUPROOT/$hostname/$fs (where $fs is derived from
# $filesystem) and will inherit properties from
# $ZPOOL$BACKUPROOT/$hostname
receive_stream() {
    local localstorage=$1
    
    runv zfs receive $option_n $option_v -F $localstorage
}

# Run the client side part of the backup
client_backup() {
    local filesystem=${1:?"${ME}: Need a filesystem to backup"}
    local prevbackuptag=${2:?"${ME}: Need a previous backup to create a" \
			     "delta from"}
    local snapname
    local bookmark
    local zfs
    
    snapname=$( generate_snapname )
    zfs=$( path_to_zfs $filesystem )
    : ${zfs:?"${ME}: Can't find a ZFS mounted as filesystem \"$filesystem\""}

    snapprev=$( get_snapshot_by_tag $zfs $prevbackuptag )
    : ${snapprev:?"${ME}: Can't find the snapshot matching tag" \
		 "\"$prevbackuptag\""}
    
    create_snapshot $zfs $snapname && \
        send_snapshot $zfs $snapprev $snapname && \
	delete_snapshot $zfs $( get_tag_from $snapprev )
}

# Find the tag of the most recent backup that is known both on the
# client and in our local store.
latest_common_backup() {
    local localstorage=$1
    local clienthost=$2
    local clientuser=$3
    local filesystem=$4
   
    local clienttags
    local serversnap
    local prevbackuptag
    
    clienttags=$(
	on_client $clienthost $clientuser \
		  __list_tags $option_d -F $filesystem
	      )

    for tag in $clienttags; do
	serversnap=$( get_snapshot_by_tag $localstorage $tag )
	if [ $serversnap ]; then
	    prevbackuptag=$tag
	    break
	fi
    done
    
    if [ -z $prevbackuptag ]; then
	echo >&2 "${ME}: Fatal -- no previous backup of $filesystem exists." \
		 "Cannot generate delta"
	exit 1
    fi

    echo $prevbackuptag
}

# Run a backup of the indicated host
server_backup() {
    local clienthost=${1:?"${ME}: Need a hostname to backup"}
    local clientuser=${2:?"${ME}: Need a username to run as on the client"}
    local fslist="${3:?\"${ME}: Need a list of filesystems to backup\"}"
    local localstorage
    local prevbackuptag
    local filesystem

    for filesystem in $fslist ; do
	# Find the tag for the latest locally held backup for this
	# host and filesystem, by comparing against the list of tags
	# extracted from the client.  If no such backup exists, then
	# fail.
	#
	# Note 2: the '__list_tags' action returns the tags with the
	# newest first, ie. sorted in reverse order.
	
	server_local_storage localstorage $clienthost $filesystem
	prevbackuptag=$( latest_common_backup $localstorage \
				  $clienthost $clientuser $filesystem )
	if [ -n "$prevbackuptag" ]; then
	    on_client $clienthost $clientuser backup $option_d $option_n \
		      $option_v -F $filesystem -p $prevbackuptag | \
		receive_stream $localstorage
	fi
    done
}

# Initial Full backup -- client side
client_full() {
    local filesystem=${1:?"${ME}: Need a filesystem to backup"}
    local snapname
    local zfs

    snapname=$( generate_snapname )
    zfs=$( path_to_zfs $filesystem )
    : ${zfs:?"${ME}: Can't find a ZFS mounted as filesystem \"$filesystem\""}
    
    create_snapshot $zfs $snapname && send_zfs $zfs $snapname
}

# Initial Full backup -- server side.  If there's a previous set of backups
# for this filesystem this will fail...
server_full() {
    local clienthost=${1:?"${ME}: Need a hostname to backup"}
    local clientuser=${2:?"${ME}: Need a username to run as on the client"}
    local fslist="${3:?\"${ME}: Need a filesystem to backup\"}"

    local localstorage

    for fs in $fslist ; do
	server_local_storage localstorage $clienthost $fs
	on_client $clienthost $clientuser full $option_d $option_n \
		  $option_v -F $fs | \
	    receive_stream $localstorage
    done
}

# Nuke all backup related bits for a filesystem client-side
# ie. snapshots and bookmarks
client_nuke() {
    local filesystem=${1:?"${ME}: Need a filesystem to clean up"}
    local snapshots
    local bookmarks
    local zfs

    zfs=$( path_to_zfs $filesystem )
    : ${zfs:?"${ME}: Can't find a ZFS mounted as filesystem \"$filesystem\""}

    snapshots=$( get_snapshots $zfs )
    
    for object in $snapshots ; do
	runv zfs destroy $option_n $option_v $object
    done

    # Apparently you can't use -n or -v with 'zfs destroy zfs#bookmark'
    bookmarks=$( get_bookmarks $zfs )

    if [ -z $option_n ]; then
	for object in $bookmarks ; do
	    runv zfs destroy $object
	done
    else
	for object in $bookmarks ; do
	    echo >&2 "--> would destroy bookmark $object"
	done
    fi
}

# Nuke all backup related bits for a host+filesystem server-side
server_nuke() {
    local clienthost=${1:?"${ME}: Need a hostname to destroy backups for"}
    local clientuser=${2:?"${ME}: Need a username to run as on the client"}
    local fslist="${3:?\"${ME}: Need a list of filesystems to destroy backups for\"}"
    local localstorage

    for filesystem in $fslist ; do
	server_local_storage localstorage $clienthost $filesystem

	runv zfs destroy -r $option_n $option_v $localstorage
    
	on_client $clienthost $clientuser nuke $option_d $option_n \
		  $option_v -F $filesystem
    done
}

# Show a report of all the backups for the given host and filesystem
server_list_backups() {
    local clienthost=${1:?"${ME}: Need a hostname to list backups for"}
    local fslist=${2:?"${ME}: Need a list of filesystems to list backups for"}
    local localstorage

    for filesystem in $fslist ; do
	server_local_storage localstorage "$clienthost" "$filesystem"

	runv zfs list -t all -o name,creation,used,mountpoint -r $localstorage
    done
}

# Parse command line options -- maybe spoofed using $SSH_ORIGINAL_COMMAND
command_line() {
    local action_opts=$1

    shift;
    
    option_d=
    option_e=
    option_f=
    option_F=
    option_h=
    option_n=
    option_p=
    option_u=
    option_v=
            
    while getopts $action_opts arg; do
	case $arg in
	    d)			# debug mode
		option_d=-d
		set -x
		;;
	    e)			# filesystem exceptions (can be repeated)
		option_e="${option_e}${option_e:+:}$OPTARG"
		;;
	    f)			# filesystem (can be repeated)
		option_f="${option_f}${option_f:+:}$OPTARG"
		;;
	    F)			# A single filesystem (__list_tags only)
		option_F=$OPTARG
		;;
	    h)			# host
		option_h=$OPTARG
		;;
	    n)			# dry-run
		option_n="-n"
		;;
	    p)			# previous backup
		option_p=$OPTARG
		;;
	    u)			# user
		option_u=$OPTARG
		;;
	    v)			# verbose
		option_v="-v"
		;;
	    z)			# SSH compression
		option_z="-z"
		;;
	    *)
		usage
		;;
	esac
    done
    
    shift $(($OPTIND - 1))
}

#
# Main program starts here.
#

if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
    # forced command from authorised_keys 
    ON_CLIENT='yes'
    : >&2 "Debug: SSH_ORIGINAL_COMMAND=$SSH_ORIGINAL_COMMAND"
    set -- $SSH_ORIGINAL_COMMAND
    shift
else
    readonly SERVERUSER=$(id -un)
fi

ACTION=$1
shift 1

# In general a client_foo() function will operate on a *single*
# filesystem whereas the equivalent server_foo() function will take a
# list of filesystems, or auto-generate one by querying the client.
case $ACTION in
    __client)			# Not allowed on commandline
	usage
	;;
    __list_tags)
	if [ "$ON_CLIENT" = 'yes' ]; then
	    command_line "dF:" "$@"
	    list_tags "$option_F"
	else
	    :			# Do nothing server side
	fi
	;;
    __list_fs)
	if [ "$ON_CLIENT" = 'yes' ]; then
	    command_line "d" "$@"
	    client_list_fs
	else
	    :			# Do nothing server side
	fi
	;;
    backup)
	if [ "$ON_CLIENT" = 'yes' ]; then
	    command_line "de:F:p:t:vz" "$@"
	    client_backup "$option_F" "$option_p"
	else
	    command_line "de:f:h:t:u:vz" "$@"
	    fslist=$( client_filesystems "$option_h" "$option_u" "$option_f" \
					 "$option_e" )
	    server_backup "$option_h" "$option_u" "$fslist"
	fi
	;;
    check)
	if [ "$ON_CLIENT" = 'yes' ]; then
	    command_line "de:F:t:u:vz" "$@"
	    client_check "$option_u" "$option_F"
	else
	    command_line "de:f:h:t:u:vz" "$@"
	    fslist=$( client_filesystems "$option_h" "$option_u" "$option_f" \
					 "$option_e" )
	    server_check "$option_h" "$option_u" "$fslist"
	fi
	;;
    full)
	if [ "$ON_CLIENT" = 'yes' ]; then
	    command_line "de:F:t:vz" "$@"
	    client_full "$option_F"
	else
	    command_line "de:f:h:t:u:vz" "$@"
	    fslist=$( client_filesystems "$option_h" "$option_u" "$option_f" \
					 "$option_e" )
	    server_full "$option_h" "$option_u" "$fslist"
	fi
	;;
    list)
	if [ "$ON_CLIENT" = 'yes' ]; then # server side only
	    :
	else
	    command_line "de:f:h:t:vz" "$@"
	    fslist=$( client_filesystems "$option_h" "$option_u" "$option_f" \
					 "$option_e" )
	    server_list_backups "$option_h" "$fslist"
	fi
	;;
    nuke)
	if [ "$ON_CLIENT" = 'yes' ]; then
	    command_line "de:F:t:v" "$@"
	    client_nuke "$option_F"
	else
	    command_line "de:f:h:t:u:v" "$@"
	    fslist=$( client_filesystems "$option_h" "$option_u" "$option_f" \
					 "$option_e" )
	    server_nuke "$option_h" "$option_u" "$fslist"
	fi
	;;
    ping)
	if [ "$ON_CLIENT" = 'yes' ]; then
	    command_line "d" "$@"
	    client_pong
	else
	    command_line "dh:u:" "$@"
	    server_ping "$option_h" "$option_u"
	fi
	;;
    setup)
	if [ "$ON_CLIENT" = 'yes' ]; then
	    :			# Do nothing
	else
	    # Print commands to run as root -- server side only
	    command_line "de:f:h:t:u:v" "$@"

	    ### Can't use the normal fslist, because we haven't set up
	    ### the filesystem tags yet ...
	    generate_setup "$option_h" "$option_u" "$option_f" # @@@
	fi
	;;
    *)
	usage
	;;
esac
#
# That's All Folks!
#
