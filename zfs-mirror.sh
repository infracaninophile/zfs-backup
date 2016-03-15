#!/bin/sh

# @{#} $Id$
#
# ZFS mirroring -- push a filesystem snapshot to a mirror machine.  We
# assume that the filesystem layout is the same on sender and receiver
# sides: the receiving ZFS is mounted in the same place as on the
# sender.  However the names of the sendming and receiving ZFSes need
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
    $ME __receive [-d] -z zfs
    $ME mirror -h hostname -u user -

EOF
    exit 1
}

# $MIRRORKEY allows password-less access to the backup user account on
# the mirror receiver machine.  For security reasons, the key should
# be set up to run 'zfs-mirror.sh __client' as a forced command: this
# will enforce running only the commands known to zfs-mirror.sh
: ${MIRRORKEY:=$( eval echo ~$SERVERUSER)/.ssh/zfs-mirror}
on_receiver() {
    local receiverhost=$1
    local receiveruser=$2
    shift 2

    ssh -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityFile=$MIRRORKEY \
	-o Compression=$option_z $receiveruser@$receiverhost $COMMAND \
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

# Identify which ZFS is mounted containing the path of interest (not
# limited to ZFS mountpoints).
path_to_zfs() {
    local var_return="$1"
    local path="$2"

    setvar "$var_return" "$(zfs list -H -t filesystem -o name $path)"
}


# Find where the named zfs is configured to be mounted. Ignores
# whether the zfs is actually mounted or not.  Only returns the
# mountpoint, so not actually the inverse of path_to_zfs().
zfs_to_path() {
    local var_return="$1"
    local zfs="$2"

    setvar "$var_return" "$(zfs list -H -t filesystem -o mountpoint $zfs)"
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
# zpool/some/zfs#bookmark #bookmark)
get_tag_from() {
    local name=$1

    echo ${name##*[@#]}
}

# Get the latest snapname used for mirroring of a particular ZFS This
# should always return a snapshot, unless things have gone pretty awry
# for quite some time.  However, we're OK if it returns a bookmark.
get_latest_mirror() {
    local var_return="$1"
    local zfs="$2"
    local latest

    latest=$( zfs list -H -d 1 -t snapshot,bookmark -o name -S creation | \
		    grep -E "[@#]$snapmatch" | head -1 )

    setvar "$var_return" "$latest"
}

# Get all of the snapnames used for mirroring of a particular ZFS.
# Choose from snapshots, bookmarks or both and order olded or newest
# first.
get_all_mirrors() {
    local var_return="$1"
    local zfs="$2"
    local type="$3"
    local order="$4"

    local sort_order
    local zobj

    case "$order" in
	reversed|descending)
	    sort_order='-s creation' # Oldest first
	    ;;
	normal|ascending)
	    sort_order='-S creation' # Newest first
	    ;;
	*)
	    echo >&2 "$ME: Sort order $order not understood:" \
		     "try one of normal, reversed. ascending, descending"
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
	    echo >&2 "$ME: $type not understood:" \
		     "try one of 'all', 'bookmark' or 'snapshot'"
	    exit 1
	    ;;
    esac

    zobj=$( zfs list -H -t $type $sort_order -o name -d 1 $zfs | \
		  grep -E "[@#]$snap_match" )

    setvar "$var_return" "$zobj"
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
# filesystem, while sender_foo() functions will read their list of
# targets from stdin, and there may be several targets.
case $ACTION in
    __client)		# Not allowed on command line
	usage
	;;
    __last_mirror)
	if [ "$ON_RECEIVER" = 'yes' ]; then
	    command_line "dF:" "$@"
	    last_mirror "$option_F"
	else
	    :			# Do nothing sender-side
	fi
	;;
    mirror)
	if [ "$ON_RECEIVER" = 'yes' ]; then
	    command_line "dF:nvz" "$@"
	    receiver_mirror "$option_F" "$option_p"
	else
	    command_line "df:h:nu:z" "$@"
	    sender_mirror "$option_h" "$option_u" "$option_f"
	fi
	;;
    *)
      usage
      ;;
esac
#
# That's All Folks!
#
