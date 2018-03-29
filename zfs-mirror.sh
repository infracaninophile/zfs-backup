#!/bin/sh

# @{#} $Id$
#
# ZFS mirroring -- push a filesystem snapshot to a mirror machine.  We
# assume that the filesystem layout is the same on sender and receiver
# sides: the receiving ZFS is mounted in the same place as on the
# sender.  However the names of the sending and receiving ZFSes need
# not be the same. To be run out of cron on the source machine at
# regular intervals (every 5 minutes is typical).
#
# Use as a forced SSH command on the receiving side.
#
# Allows mirroring to be run entirely as a non-privileged user,
# although it does require allowing that user sufficient ZFS
# privileges that they can unmount or destroy the mirrored filesystem.

export PATH="/sbin:/usr/sbin:/usr/local/sbin:/bin:/usr/bin:/usr/local/sbin"

readonly ME=$(basename $0)
readonly COMMAND=$0
readonly TAG='zm-'
ACTION=

usage() {
    cat >&2 <<EOF
$ME: Usage:
    $ME __client
    $ME __list_tags [-d] -F filesystem
    $ME mirror [-dnvz] -h hostname -u user -f filesystem:...
    $ME init [-dnvz] -h hostname -u user -f filesystem:...

'$ME __client' For internal use: should only be run as a forced
command from the mirror user's authorized_keys file.  It takes no
options.

'$ME __list_tags' For internal use on the receiving host only.  List
the mirroring tags known for the given filesystem, in date order,
newest first.

'$ME mirror' Snapshot the ZFSes containing the listed filesystems and
send an incemental stream of all changes beteen the previous snapshot
and this one to the receiving host.

'$ME init' Snapshot the ZFSes containing the listed filesystems and
send a full stream of the filesystem upto this snapshot to the
receiving host.  After this, it will be possible to send incremental
updates via '$ME mirror ...'

Options:
    -d Debug mode: trace program execution to stderr.
    -f Filesystems to mirror -- as a colon separated list of the full paths
       from the root directory.  Can be given multiple times: additional
       filesystem will be added to the list.
    -h Hostname to mirror the filesystems onto.
    -n Dry-run mode: show what would be done without committing any changes.
    -u Username on the receiving host.
    -v Verbose operation: print information about progress to stderr.
    -z Compress data over the wire.  Enables SSH's Compression option.

Compressing SSH traffic may or may not improve performance: you will
have to experiment to find the best setting.  In general, compression
only helps on relatively low bandwidth, high RTT connections, and
where content is intrinsically compressible.

Always run this script on the sending server as the same user, who is
assumed to own the SSH key used for access.

The user on the receiving server is assumed to have full permissions
to receive the serialized ZFS data and to mount and unmount the
destination filesystem.  You will need to set the vfs.usermount sysctl
to 1 and make sure the user owns the mountpoint directory that the
mirrored filesystem is mounted on top of.  This will be hidden once
the mirrored filesystem is mounted.

EOF
    exit 1
}

# $MIRRORKEY allows password-less access to the backup user account on
# the mirror receiver machine.  For security reasons, the key should
# be set up to run 'zfs-mirror.sh __client' as a forced command: this
# will enforce running only the commands known to zfs-mirror.sh
: ${MIRRORKEY:=$( eval echo ~$SERVERUSER)/.ssh/zfs-mirror}
on_receiver() {
    local receiverhost="$1"
    local receiveruser="$2"
    shift 2

    ssh -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityFile=$MIRRORKEY \
	-o Compression=$option_z $receiveruser@$receiverhost $COMMAND \
	${1+$@} || exit 1
}

# Echo the command line to stderr if in verbose mode, then run the
# command
runv() {
    if [ -n $option_v ]; then
	if [ "$ON_RECEIVER" = 'yes' ]; then
	    echo >&2 "--> $@"
	else
	    echo >&2 "==> $@"
	fi
    fi
    "$@"
}

# Identify which ZFS is mounted containing the path of interest (not
# limited to ZFS mountpoints).  Beware of having a local variable of
# the same name as passed in via $var_return -- that doesn't end well.
path_to_zfs() {
    local var_return="$1"
    local path="$2"
    local _zfs

    _zfs=$(zfs list -H -t filesystem -o name $path)
    : ${_zfs:?${ME}: Cannot find a ZFS mounted as filesystem \"$path\"}

    setvar "$var_return" "$_zfs"
}


# Find where the named zfs is configured to be mounted. Ignores
# whether the zfs is actually mounted or not.  Only returns the
# mountpoint, so not actually the inverse of path_to_zfs().
zfs_to_path() {
    local var_return="$1"
    local zfs="$2"
    local _mountpoint

    _mountpoint=$(zfs list -H -t filesystem -o mountpoint $zfs)
    : ${_mountpoint:?${ME}: Cannot find a mountpoint for ZFS \"$zfs\"}

    setvar "$var_return" "$_mountpoint"
}

# A unique snapname is used for each mirrored zfs -- the snapname is
# deliberately distinct from the snapshot name used by zfs-backup.sh,
# so a ZFS can be both mirrored to one machine and backed up to
# another.
#
# The snapshots created for mirroring will be retained for a
# configurable time, after which they are converted to bookmarks,
# which are retained for a further, longer (also configurable) period.
#
# 8 bytes of randomness => 16 hex digits = 2^64 = 18446744073709551616
# different possibilities, which should be enough that we just don't
# need to worry about collisions.
generate_snapname() {
    local var_return="$1"

    setvar "$var_return" "${TAG}$(openssl rand -hex 8)"
}

# A regex to match the snapshot format.
readonly snap_match="${TAG}[[:xdigit:]]{16}$"

# Extract the $tag from a fully or partially qualified snapshot or
# bookmark name (eg zpool/some/zfs@snapname @snapname
# zpool/some/zfs#bookmark #bookmark) listed on stdin, one per line.
extract_tags() {
    local name

    while read name; do
	echo ${name##*[@#]}
    done
}

# Create a snapshot
create_snapshot() {
    local zfs="$1"
    local snapname="$2"

    if [ -z $option_n ]; then
	runv zfs snapshot "$zfs@$snapname"
    fi
}

# Get all of the snapnames used for mirroring of a particular ZFS.
# Choose from snapshots, bookmarks or both and order olded or newest
# first.
get_all_mirror_tags() {
    local var_return="$1"
    local zfs="$2"
    local type="$3"
    local order="$4"

    local sort_order
    local _zobj

    case "$order" in
	reversed|descending)
	    sort_order='-s creation' # Oldest first
	    ;;
	normal|ascending)
	    sort_order='-S creation' # Newest first
	    ;;
	*)
	    echo >&2 "$ME: Sort order $order not understood:" \
		     "try one of normal, reversed, ascending, descending"
	    exit 1
	    ;;
    esac

    case "$type" in
	all)
	    type='snapshot,bookmark'
	    ;;
	bookmark|snapshot)
	    ;;
	*)
	    echo >&2 "$ME: Type $type not understood:" \
		     "try one of 'all', 'bookmark' or 'snapshot'"
	    exit 1
	    ;;
    esac

    _zobj=$( zfs list -H -t $type $sort_order -o name -d 1 $zfs | \
		  grep -E "[@#]$snap_match" | extract_tags )

    setvar "$var_return" "$_zobj"
}

# List the tags for all the mirror copies (snapshots or bookmarks) known
# on the named filesystem, *newest* first.
list_tags() {
    local filesystem="${1:?${ME}: Need a filesystem to list mirroring tags for}"
    local prevmirrors
    local zfs
    local mirror

    path_to_zfs zfs $filesystem
    get_all_mirror_tags prevmirrors $zfs all normal

    echo $prevmirrors
}

# Find the tag of the most recent backup that is known both on the
# client and in our local store.  Server-side this will always be a
# snapshot.
latest_common_tag() {
    local var_return="$1"
    local hostname="$2"
    local username="$3"
    local local_zfs="$4"
    local filesystem="$5"

    local receivertags
    local sendertags
    local serversnap
    local _prevmirrortag

    get_all_mirror_tags sendertags $local_zfs all normal

    receivertags=$(
	on_receiver $hostname $username \
		    __list_tags $option_d -F $filesystem
	      )

    for sendertag in $sendertags ; do
	for receivertag in $receivertags ; do
	    if [ "$sendertag" = "$receivertag" ]; then
		_prevmirrortag=$sendertag
		break 2
	    fi
	done
    done

    if [ -z $_prevmirrortag ]; then
	echo >&2 "${ME}: Fatal -- no previous common mirrored state of" \
		 "$filesystem exists. Cannot generate delta"
	exit 1
    fi

    setvar "$var_return" "$_prevmirrortag"
}

# On the client: send a snapshot of a filesystem to the backup server.
# If the send doesn't succeed, destroy the snapshot.  zfs send -RI
# does not replicate bookmarks to the mirrored filesystem, but it does
# delete snapshots that have been bookmarked and then removed, which
# makes bookmarks fairly useless for mirroring to provide an online
# spare server: if you wanted to reverse the direction of mirroring,
# you'ld need the same snapshots / bookmarks either side.
send_snapshot() {
    local zfs="$1"
    local previous_snapshot="$2"
    local this_snapshot="$3"

    if [ -z $option_n ]; then
	runv zfs send -PRI $previous_snapshot "$zfs@$this_snapshot" || \
	    runv zfs destroy "$zfs@$this_snapshot"
    fi
}

# Initial backup -- send the whole filesystem snapshot to the backup
# server This should only ever happen one time, otherwise it will wipe
# out the snapshot history on the backup server.  If the send doesn't
# succeed, destroy the snapshot.
send_zfs() {
    local zfs="$1"
    local snapname="$2"

    runv zfs send $option_n $option_v -PR "$zfs@$snapname" || \
	runv zfs destroy $option_n "$zfs@$snapname"
}

# This is used receiver-side for both mirroring and the initial copy
# of the ZFS.
receiver_mirror() {
    local filesystem="${1?${ME}: Need a filesystem for mirroring}"
    local zfs

    path_to_zfs zfs $filesystem
    runv zfs receive $option_n $option_v -F $zfs
}

# Send an incremental update from the previous snapshot known on the
# receiving host to the current, freshly created snapshot
sender_mirror_one_filesystem() {
    local hostname="$1"
    local username="$2"
    local filesystem="$3"
    local zfs
    local snapname
    local prev_snapname

    path_to_zfs zfs "$filesystem"

    latest_common_tag prev_snapname "$hostname" "$username" "$zfs" \
		       "$filesystem"

    generate_snapname snapname
    create_snapshot "$zfs" "$snapname"

    send_snapshot "$zfs" "$prev_snapname" "$snapname" | \
	on_receiver "$hostname" "$username" mirror $option_d $option_n \
		    $option_v -F $filesystem
}

sender_mirror() {
    local hostname="${1:?${ME}: Need a hostname to mirror to}"
    local username="${2:?${ME}: Need a username to run mirroring as}"
    local filesystems="${3:?${ME}: Need a list of filesystems to mirror}"
    local fs

    for fs in $filesystems ; do
	sender_mirror_one_filesystem "$hostname" "$username" "$fs"
    done
}

sender_init_one_filesystem() {
    local hostname="$1"
    local username="$2"
    local filesystem="$3"
    local zfs
    local snapname

    path_to_zfs zfs "$filesystem"
    generate_snapname snapname
    create_snapshot "$zfs" "$snapname"

    send_zfs "$zfs" "$snapname" | \
	on_receiver $hostname $username init $option_d $option_n \
		    $option_v -F $filesystem
}

sender_init() {
    local hostname="${1:?${ME}: Need a hostname to mirror to}"
    local username="${2:?${ME}: Need a username to run mirroring as}"
    local filesystems="${3:?${ME}: Need a list of filesystems to mirror}"

    local fs

    for fs in $filesystems ; do
	sender_init_one_filesystem "$hostname" "$username" "$fs"
    done
}

# Parse command line options -- maybe spoofed using $SSH_ORIGINAL_COMMAND
command_line() {
    local action_opts=$1

    shift;

    option_d=
    option_f=
    option_F=
    option_h=
    option_n=
    option_u=
    option_v=
    option_z="no"

    while getopts $action_opts arg; do
	case $arg in
	    d)			# debug mode
		option_d=-d
		set -x
		;;
	    f)			# filesystem (can be repeated)
		option_f="${option_f}${option_f:+ }$( echo $OPTARG | tr ':' ' ' )"
		;;
	    F)			# A single filesystem (receiver only)
		option_F=$OPTARG
		;;
	    h)			# host
		option_h=$OPTARG
		;;
	    n)			# dry-run
		option_n="-n"
		;;
	    u)			# user
		option_u=$OPTARG
		;;
	    v)			# verbose
		option_v="-v"
		;;
	    z)			# SSH compression
		option_z="yes"
		;;
	    *)
		usage
		;;
	esac
    done

    shift $(($OPTIND - 1))
}

#
# Main program starts here
#

if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
    # forced command from authorised_keys
    ON_RECEIVER='yes'
    : >&2 "Debug: SSH_ORIGINAL_COMMAND=$SSH_ORIGINAL_COMMAND"
    set -- $SSH_ORIGINAL_COMMAND
    shift
else
    readonly SERVERUSER=$(id -un)
fi

ACTION=$1
shift 1

# In general receiver_foo() functions will operate on a single
# filesystem, while sender_foo() functions will may have several
# filesystem targets.
case $ACTION in
    __client)		# Not allowed on command line
	usage
	;;
    __list_tags)
	if [ "$ON_RECEIVER" = 'yes' ]; then
	    command_line "dF:" "$@"
	    list_tags "$option_F"
	else
	    :			# Do nothing sender-side
	fi
	;;
    mirror)
	if [ "$ON_RECEIVER" = 'yes' ]; then
	    command_line "dF:nvz" "$@"
	    receiver_mirror "$option_F"
	else
	    command_line "df:h:nu:vz" "$@"
	    sender_mirror "$option_h" "$option_u" "$option_f"
	fi
	;;
    init)
	if [ "$ON_RECEIVER" = 'yes' ]; then
	    command_line "dF:nvz" "$@"
	    receiver_mirror "$option_F"
	else
	    command_line "df:h:nu:vz" "$@"
	    sender_init "$option_h" "$option_u" "$option_f"
	fi
	;;
    *)
      usage
      ;;
esac
#
# That's All Folks!
#
