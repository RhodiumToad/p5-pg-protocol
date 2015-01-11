# -*- Perl -*-

# Low-level protocol package for PostgreSQL.
# Copyright 2008-2015+ Andrew Gierth. PostgreSQL licence.
# NO WARRANTY; EXPERIMENTAL CODE; MAY EXPLODE IF MISHANDLED.
# (BEWARE OF DOG.)

# Roadmap:
#
#   Main user-facing module:
#     Net::PGSQL
#
#   Transport-specific subclasses:
#     Net::PGSQL::INET
#     Net::PGSQL::UNIX
#     Net::PGSQL::SSLConn
#
#   Protocol stuff:
#     Net::PGSQL::Protocol3
#
#   Messages sent to server:
#     Net::PGSQL::Protocol3::FrontendMsg
#     Net::PGSQL::Protocol3::FrontendMsg::{message types}
#
#   Messages received from server:
#     Net::PGSQL::Protocol3::BackendMsg
#     Net::PGSQL::Protocol3::BackendMsg::{message types}
#
#
# Todo:
#
#   Lots.
#
#   Notably, haven't made any serious effort yet to address encoding
#   issues. Everything here assumes we're dealing with things that
#   look like byte strings.
#
#   The POD is here mainly for the benefit of people reading the code,
#   I haven't checked whether it produces readable docs.
#

#----------------------------------------------------------------------------

=head1 NAME

    Net::PGSQL - low-level protocol access for PostgreSQL

=head1 SYNOPSIS

    use Net::PGSQL;

    my $conn = Net::PGSQL->new(host => 'localhost', port => 5432);
    $conn->StartupRequest(user => 'postgres', dbname => 'postgres');
    my $packet = $conn->waitpacket;
    ...

=head1 FUNCTIONS

See Net::PGSQL::Protocol3 for most of the protocol-level functions.

=over 4

=cut

package Net::PGSQL;

use strict;
use IO::Socket qw(SOCK_STREAM IPPROTO_TCP TCP_NODELAY);
use IO::Socket::INET ();
use IO::Socket::UNIX ();

BEGIN {
    our $VERSION = '0.03';
}

use parent -norequire, qw(Net::PGSQL::Protocol3);

use constant DEFAULT_SOCKET_PATH => '/tmp';
use constant DEFAULT_PORT => 5432;

=item new ARGS

Create a connection from specified args, passed hash-style.

Only the connection-level args are passed here. Recognized keys
are C<host>, C<port>, C<connect_timeout>, C<blocking>. The socket
is actually always in nonblocking mode after connect; the C<blocking>
parameter only affects whether writes will block.

SSL is not handled here, though connections can be upgraded to SSL
before sending the startup message.

=cut

sub new
{
    my $self = shift;
    my $type = ref($self) || $self;
    my %args = @_;
    my $connargs = _connection_args(\%args);
    my $obj;

    if (defined $connargs->{Proto})
    {
	$obj = Net::PGSQL::INET->IO::Socket::INET::new()
	    or return undef;
	$obj->configure($connargs)
	    or return undef;
	$obj->setsockopt(IPPROTO_TCP, TCP_NODELAY, 1);
    }
    else
    {
	$obj = Net::PGSQL::UNIX->IO::Socket::UNIX::new()
	    or return undef;
	$obj->configure($connargs)
	    or return undef;
    }

    ${*$obj}{net_pgsql_args} = \%args;

    $obj->blocking(0);

    $obj->_init();
    
    return $obj;
}

=item ssl_active

Returns true if this connection is over SSL.

=cut

sub ssl_active
{
    return 0;
}

=item ssl_available

Returns true if the required modules for SSL support can be loaded.

=cut

sub ssl_available
{
    Net::PGSQL::SSLConn::_ssl_init();
}

=item wait_for_input TIMEOUT

Wait for a read-ready condition.

=cut

sub wait_for_input
{
    my ($self,$timeout) = @_;
    my $sel = IO::Select->new($self);
    return $sel->can_read($timeout);
}

=item wait_for_output

Wait for a write-ready condition.

=cut

sub wait_for_output
{
    my ($self) = @_;
    my $sel = IO::Select->new($self);
    return $sel->can_write();
}

=item input_pending

Returns the number of bytes pending between the socket syscalls and
the protocol parser.

=cut

sub input_pending
{
    return 0;
}

=item set_handler NAME SUB

The handler name can be C<read_error> or C<write_error>. The sub is called
with the connection object and the C<$!> value.

=cut

sub set_handler
{
    my ($self,$name,$subr) = @_;
    $$self{"net_pgsql_handler_$name"} = $subr;
}


# extract the args wanted by IO::Socket from our original args.

sub _connection_args
{
    my $args = shift;
    my $connargs = {};
    my $host = $args->{host};
    my $port = $args->{port} || DEFAULT_PORT;

    $connargs->{Type} = SOCK_STREAM;

    if (!defined($host) or $host =~ m{^/})
    {
	my $path = $host || $args->{path} || DEFAULT_SOCKET_PATH;
	$connargs->{Peer} = sprintf("%s/.s.PGSQL.%d",$path,$port);
    }
    else
    {
	$connargs->{Proto} = 'tcp';
	$connargs->{PeerPort} = $port;
	$connargs->{PeerAddr} = $host;
    }

    $connargs->{Timeout} = $args->{connect_timeout};

    $connargs->{Blocking} = 0
	if (defined($args->{blocking}) and !$args->{blocking});
	
    return $connargs;
}

# Try and upgrade to SSL. This will re-bless the object if successful

sub _sslify
{
    my $self = shift;
    if (Net::PGSQL::SSLConn::_ssl_init())
    {
	Net::PGSQL::SSLConn->start_SSL($self);
	$self->blocking(0);
    }
    return $self->ssl_active;
}

# Low-level read, separated out because SSL needs to override it to
# do nonblocking correctly. Returns 0-but-true if no input ready,
# 0 for EOF, undef on error, or bytes read.

sub _read_one_buffer
{
    my ($self, $bufref) = @_;
    my $len = $self->sysread($$bufref, $self->_bufsize, length($$bufref));
    return $len if defined $len;
    return $self->_read_error($!) unless $!{EAGAIN} or $!{EWOULDBLOCK};
    return "0E0";
}

# Low-level write, separated out because SSL needs to override it to
# do nonblocking correctly. Returns 0 if would block, undef on error,
# or bytes written.

sub _write_one_buffer
{
    my ($self, $bufref, $len, $pos) = @_;
    my $rlen = $self->syswrite($$bufref, $len, $pos);
    return $rlen if defined $rlen;
    return $self->_write_error($!) unless $!{EAGAIN} or $!{EWOULDBLOCK};
    return 0;
}

sub _read_error
{
    my ($self,$err) = @_;
    ${*$self}{net_pgsql_error} = $err;
    $$self{net_pgsql_handler_read_error}->($self,$err)
	if defined($$self{net_pgsql_handler_read_error});
    return undef;
}

sub _write_error
{
    my ($self,$err) = @_;
    ${*$self}{net_pgsql_write_error} = $err;
    $$self{net_pgsql_handler_write_error}->($self,$err)
	if defined($$self{net_pgsql_handler_write_error});
    return undef;
}

=back

=cut

#----------------------------------------------------------------------------

package Net::PGSQL::INET;

use strict;

use parent -norequire, qw(Net::PGSQL IO::Socket::INET);

use constant DEFAULT_BUFSIZE => 8192;

#----------------------------------------------------------------------------

package Net::PGSQL::UNIX;

use strict;

use parent -norequire, qw(Net::PGSQL IO::Socket::UNIX);

use constant DEFAULT_BUFSIZE => 8192;

#----------------------------------------------------------------------------

package Net::PGSQL::SSLConn;

use strict;

use constant DEFAULT_BUFSIZE => 16384;

use parent -norequire, qw(Net::PGSQL);

sub _ssl_init;

{
    my $SSL_ENABLE = undef;

    # Various jiggery-pokery to load the underlying module only if asked.

    sub _ssl_init
    {
	return $SSL_ENABLE if defined $SSL_ENABLE;
	{
	    local $@;
	    if (eval 'use IO::Socket::SSL qw($SSL_ERROR SSL_WANT_READ SSL_WANT_WRITE); 1')
	    {
		$SSL_ENABLE = 1;
		our @ISA;
		push @ISA, 'IO::Socket::SSL';
	    }
	    else
	    {
		$SSL_ENABLE = 0;
	    }
	}
	return $SSL_ENABLE;
    }
}

sub _ssl_nonblock_state
{
    our $SSL_ERROR;
    return
	($SSL_ERROR == &SSL_WANT_READ) ? 1 :
	($SSL_ERROR == &SSL_WANT_WRITE) ? -1 : 0;
}

# These below override the default methods in Net::PGSQL.

sub ssl_active
{
    return 1;
}

sub input_pending
{
    return shift->pending();
}

sub wait_for_input
{
    my ($self,$timeout) = @_;
    return 1 if $self->pending() > 0;
    my $sel = IO::Select->new($self);
    my $state = ${*$self}{net_pgsql_ssl_state} || 1;
    return ($state == 1) ? $sel->can_read($timeout) : $sel->can_write($timeout);
}

sub wait_for_output
{
    my ($self) = @_;
    my $sel = IO::Select->new($self);
    my $state = ${*$self}{net_pgsql_ssl_state} || -1;
    return ($state == 1) ? $sel->can_read() : $sel->can_write();
}

sub _read_one_buffer
{
    my ($self, $bufref) = @_;
    ${*$self}{net_pgsql_ssl_state} = 0;
    my $len = $self->sysread($$bufref, $self->_bufsize, length($$bufref));
    return $len if defined $len;
    return $self->_read_error($!) unless $!{EAGAIN} or $!{EWOULDBLOCK};
    ${*$self}{net_pgsql_ssl_state} = _ssl_nonblock_state();
    return "0E0";
}

sub _write_one_buffer
{
    my ($self, $bufref, $len, $pos) = @_;
    ${*$self}{net_pgsql_ssl_state} = 0;
    my $rlen = $self->syswrite($$bufref, $len, $pos);
    return $rlen if defined $rlen;
    return $self->_write_error($!) unless $!{EAGAIN} or $!{EWOULDBLOCK};
    ${*$self}{net_pgsql_ssl_state} = _ssl_nonblock_state();
    return 0;
}

#----------------------------------------------------------------------------

=head1 NAME

    Net::PGSQL::Protocol3 - low-level protocol access for PostgreSQL

=head1 FUNCTIONS

See Net::PGSQL for constructors.

=over 4

=cut

package Net::PGSQL::Protocol3;

use strict;
use Errno;
use IO::Select;
use Scalar::Util qw(blessed);

# for packets larger than this we assume it's worth avoiding extra
# data copying cycles. A threshold of 4*bufsize is also used here,
# since bufsize might vary.

use constant LARGE_PACKET => 65536;

# probably not ideal

sub protocol_error
{
    my ($self,$err) = @_;
    die "$err\n";
}

sub protocol_warn
{
    my ($self,$err) = @_;
    warn "$err\n";
}

# trivial state machine for startup, ssl, main processing
#
# State functions return 0 if the input is processed, 1 if a partial
# input packet requires another read pass. The state function removes
# processed input data from the passed buffer.

sub _state_start
{
    my ($self,$bufref) = @_;
    if (length($$bufref))
    {
	$self->protocol_error("unexpected data received in state_start");
    }
    else
    {
	$self->protocol_warn("EOF during connection startup");
    }
    return 0;
}

sub _state_sslreq
{
    my ($self,$bufref) = @_;
    if ($$bufref =~ /^([SN])/)
    {
	if ($1 eq 'S')
	{
	    $self->_sslify();
	}
	substr($$bufref,0,1,'');
    }
    else
    {
	$self->protocol_warn("unexpected message type '@{[substr($$bufref,0,1)]}' in state_sslreq");
    }
    ${*$self}{net_pgsql_state} = \&_process;
    return $self->_process($bufref) if length($$bufref);
    return 0;
}

# this one does the real work; parse as many backend messages as
# available and put them on the recvqueue.

sub _process
{
    my ($self,$bufref) = @_;
    my $partial = 0;
    my $pos = 0;
    my $len = length($$bufref);
    my $q = ${*$self}{net_pgsql_recvqueue};
    while ($len)
    {
	++$partial, last unless $len >= 5;
	my ($msgtype,$msglen) = unpack("\@$pos a1N",$$bufref);
	++$msglen;  # msglen includes itself, but not msgtype
	++$partial, last unless $len >= $msglen;
	push @$q, $self->_parse($msgtype,substr($$bufref,$pos+5,$msglen-5));
	$pos += $msglen;
	$len -= $msglen;
    }
    substr($$bufref,0,$pos,'');
    return $partial;
}

# Given a message type and data received, turn it into a packet object.

sub _parse
{
    my ($self,$msgtype,$data) = @_;
    my $msg = Net::PGSQL::Protocol3::BackendMsg->new($msgtype,$data);
    $self->protocol_warn("unexpected message type $msgtype") unless $msg;
    $msg ? ($msg) : ();
}

# Invoke the state function.

sub _call_state
{
    my $self = shift;
    my $func = ${*$self}{net_pgsql_state};
    $self->$func(@_);
}

=item consume_input

Read any available input and turn it into packets. Won't block.

Returns a false value on error, or on EOF if the packet queue is empty.
Returns 0-but-true if there are no packets available yet. Returns E<gt>0
if packets are available.

=cut

sub consume_input
{
    my $self = shift;
    my $bufref = ${*$self}{net_pgsql_buffer};
    my $q = ${*$self}{net_pgsql_recvqueue};

    do
    {
	my $len = $self->_read_one_buffer($bufref);
	if (!defined($len))
	{
	    return undef;
	}
	elsif (!$len)
	{
	    ${*$self}{net_pgsql_eof} = 1;
	    $self->_call_state($bufref);
	    $self->protocol_warn("incomplete packet at EOF") if length($$bufref);
	    return scalar @$q;
	}
	elsif ($len == 0)
	{
	    return (scalar @$q) || "0E0";
	}
    }
    while ($self->_call_state($bufref));

    return scalar @$q;
}

sub err
{
    my $self = shift;
    return ${*$self}{net_pgsql_error};
}

sub eof
{
    my $self = shift;
    return ${*$self}{net_pgsql_eof};
}

=item getpacket

Return one packet if one is available, otherwise returns undef.

Will call C<consume_input> if the queue is empty.

=cut

sub getpacket
{
    my $self = shift;
    my $q = ${*$self}{net_pgsql_recvqueue};
    do
    {
	return shift @$q if @$q;
    }
    while $self->consume_input() > 0;
    return undef;
}

=item waitpacket

Return one packet if available, otherwise block. Returns undef
only if the connection is closed or breaks.

=cut

sub waitpacket
{
    my $self = shift;
    my $q = ${*$self}{net_pgsql_recvqueue};
    for (;;)
    {
	return shift @$q if @$q;
	my $status = $self->consume_input;
	return undef unless $status;
	$self->wait_for_input unless $status > 0;
    }
}

sub _init
{
    my $self = shift;
    my $recvbuf = "";
    my $sendbuf = "";
    my $args = ${*$self}{net_pgsql_args};
    ${*$self}{net_pgsql_nonblocking} = (defined($args->{blocking}) and !$args->{blocking});
    ${*$self}{net_pgsql_error} = 0;
    ${*$self}{net_pgsql_eof} = 0;
    ${*$self}{net_pgsql_state} = \&_state_start;
    ${*$self}{net_pgsql_buffer} = \$recvbuf;
    ${*$self}{net_pgsql_sendbuf} = \$sendbuf;
    ${*$self}{net_pgsql_sendpos} = 0;
    ${*$self}{net_pgsql_sendqlen} = 0;
    ${*$self}{net_pgsql_sendqueue} = [];
    ${*$self}{net_pgsql_recvqueue} = [];
    ${*$self}{net_pgsql_bufsize} = undef;
}

sub _bufsize
{
    my $self = shift;
    return ${*$self}{net_pgsql_bufsize} || $self->DEFAULT_BUFSIZE;
}

sub set_bufsize
{
    my ($self,$sz) = @_;
    ${*$self}{net_pgsql_bufsize} = $sz;
}

=item enqueue PACKET...

Add zero or more packets to the sending queue and try draining the
queue to the server. (If no packet is forcing a flush, there will only
be an actual write if there's enough buffered to be worth it.)

Normally not needed since the packet functions enqueue directly.

=cut

sub enqueue
{
    my $self = shift;
    my $q = ${*$self}{net_pgsql_sendqueue};
    my $qlen = 0;
    my $flush = undef;
    for my $msg (@_)
    {
	push @$q, $msg;
	$qlen += $msg->len;
	${*$self}{net_pgsql_flush} ||= 1 if $msg->_flush;
    }
    ${*$self}{net_pgsql_sendqlen} += $qlen;
    $self->drain_output();
}

=item flush

Force the sending queue to be sent to the server. Not normally needed
since packet types that need it trigger it themselves.

=cut

sub flush
{
    my $self = shift;
    ${*$self}{net_pgsql_flush} ||= 1;
    $self->drain_output();
}

=item drain_output

Send data to the server if it seems appropriate. In nonblocking mode
will return 0-but-true rather than wait for writability; in blocking
mode, it will wait until either all data is sent, in the case of a
forced flush, or when the buffer is below threshold.

=cut

sub drain_output
{
    my $self = shift;
    my $q = ${*$self}{net_pgsql_sendqueue};
    my $qlen = ${*$self}{net_pgsql_sendqlen};
    my $force = ${*$self}{net_pgsql_flush};
    my $len = length(${${*$self}{net_pgsql_sendbuf}}) - ${*$self}{net_pgsql_sendpos};

    return 1
	unless $force or ($qlen + $len) > 2 * ($self->_bufsize);

    do
    {
	until ((my $res = $self->_flushonce) > 0)
	{
	    return undef if !defined($res);
	    return "0E0" if ${*$self}{net_pgsql_nonblocking};
	    $self->wait_for_output;
	}
    }
    while ($force
	   and (@$q
		or (length(${${*$self}{net_pgsql_sendbuf}}) - ${*$self}{net_pgsql_sendpos}) > 0));

    return 1;
}

# Guts of output to server.

sub _flushonce
{
    my $self = shift;
    my $q = ${*$self}{net_pgsql_sendqueue};
    my $qlen = ${*$self}{net_pgsql_sendqlen};
    my $force = ${*$self}{net_pgsql_flush};
    my $bufref = ${*$self}{net_pgsql_sendbuf};
    my $pos = ${*$self}{net_pgsql_sendpos};
    my $len = length($$bufref) - $pos;
    my $defbufsize = $self->_bufsize;

    # $bufref might at this point be an actual buffer, or it might
    # be the object reference of a large message. Either way we can
    # treat it as a scalar ref, but be careful.

    # if there's a lot of buffered data, start by writing out most of
    # it, but leaving enough to ensure that we don't do a small write
    # after. If we've got two full buffers worth in the queue, we can
    # drain the buffer entirely; otherwise, leave one buffer's worth
    # which we will pad later. Our aim here is to always write in
    # chunks of at least DEFAULT_BUFSIZE (but not normally more than
    # twice that unless dealing with large messages)

  OUTER:
    {
	while ($len >= 2 * $defbufsize
	       or ($len > $defbufsize and ($qlen >= 2 * $defbufsize))
	       or ($force and $len > 0 and $qlen == 0))
	{
	    my $target =
		($force and $qlen == 0)	? $len :
		($qlen >= 2 * $defbufsize) ? $len - ($len % $defbufsize) :
		$len - $defbufsize - ($len % $defbufsize);
	    my $res = $self->_write_one_buffer($bufref, $target, $pos);
	    return $res unless ($res > 0);
	    $len -= $res;
	    ${*$self}{net_pgsql_sendpos} = ($pos += $res);
	}
	
	if (blessed($bufref))
	{
	    # must have been a large message object rather than a real
	    # buffer, so free it and create a new scalar buf
	    
	    my $newbuf = do { my $buf = substr($$bufref,$pos); \$buf };
	    ${*$self}{net_pgsql_sendbuf} = ($bufref = $newbuf);
	}
	elsif ($len == 0)
	{
	    $$bufref = "";
	}
	else
	{
	    substr($$bufref,0,$pos,"");
	}
	
	${*$self}{net_pgsql_sendpos} = ($pos = 0);

	if ($len == 0 and !@$q)
	{
	    ${*$self}{net_pgsql_flush} = 0;
	    return 1;
	}
	
	return 1 unless $force or ($len + $qlen) >= 2 * $defbufsize;
	
	# at this point we know that @$q is nonempty, because either $qlen
	# > 0 (since $len < 2*DEFAULT_BUFSIZE), or $force is true in which
	# case the top loop will have emptied the buffer and we would have
	# returned above. Pull from the queue and send until either we have
	# less than a buffer left (or nothing if $force), or we block
	
	while ($qlen > 0)
	{
	    my $msg = $q->[0];
	    my $msglen = $msg->len;
	    
	    if ($msglen >= LARGE_PACKET and $msglen >= 4 * $defbufsize)
	    {
		# big enough that we don't want to copy it.
		# but we want to slice off up to 2*DEFAULT_BUFSIZE to pad out
		# the buffer if it isn't empty yet.

		if ($len > 0)
		{
		    my $olen = $len;
		    my $padsize = 2 * $defbufsize - $len;
		    $$bufref .= substr($$msg,0,$padsize);
		    $len += $padsize;
		    while ($pos < $olen)
		    {
			my $res = $self->_write_one_buffer($bufref, $len, $pos);
			unless ($res > 0)
			{
			    # remove the extra data from the buffer so that
			    # the state is consistent for next time.
			    substr($$bufref,$olen,length($$bufref)-$olen,"");
			    return $res;
			}
			$len -= $res;
			${*$self}{net_pgsql_sendpos} = ($pos += $res);
		    }
		    # at this point the original buf is drained, and
		    # $pos - $olen reflects how much of the big packet
		    # we've consumed
		    $pos -= $olen;
		}
		
		${*$self}{net_pgsql_sendbuf} = ($bufref = $msg);
		${*$self}{net_pgsql_sendpos} = $pos;
		${*$self}{net_pgsql_sendqlen} = ($qlen -= $msglen);
		$len = length($$bufref) - $pos;
		shift @$q;
		redo OUTER;
	    }

	    # small packet. Just append to the buffer and loop.
	    # restart the whole process once we have enough to be
	    # worthwhile.

	    $$bufref .= $$msg;
	    $len += $msglen;
	    ${*$self}{net_pgsql_sendqlen} = ($qlen -= $msglen);
	    shift @$q;
	    redo OUTER if $len >= 2 * $defbufsize;
	}

	redo OUTER if $force;
    }

    return 1;
}

=item SSLRequest

Create and enqueue an SSLRequest message, and set up the state to
process an affirmative response by initiating SSL on the socket.

TODO: stuff with certs.

=cut

sub SSLRequest
{
    my $self = shift;
    return undef unless $self->ssl_available;
    ${*$self}{net_pgsql_state} = \&_state_sslreq;
    return $self->enqueue(Net::PGSQL::Protocol3::FrontendMsg::SSLRequest->new(@_));
}

=item StartupRequest ARGS...

Create and enqueue a StartupRequest. ARGS is a hash-style list. The
C<user> parameter is required by the server.

=cut

sub StartupRequest
{
    my $self = shift;
    ${*$self}{net_pgsql_state} = \&_process;
    return $self->enqueue(Net::PGSQL::Protocol3::FrontendMsg::StartupRequest->new(@_));
}

=item CancelRequest PID KEY

Create and enqueue a CancelRequest.

=cut

sub CancelRequest
{
    my $self = shift;
    ${*$self}{net_pgsql_state} = \&_state_start;
    return $self->enqueue(Net::PGSQL::Protocol3::FrontendMsg::CancelRequest->new(@_));
}

=item MESSAGETYPE ARGS...

Every frontend message type has a corresponding method call which
creates and enqueues a message of that type.

=cut

=back

=cut

#----------------------------------------------------------------------------

# A small package management thing to encapsulate some of the code generation.

package Net::PGSQL::PackageMgr;

use strict;
use Carp;
use Sub::Name;
use parent qw(Package::Stash);

# define NAME as CODE in the package, naming the function object

sub defun
{
    my ($self,$name,$code) = @_;
    @_ = ($self,
	  '&' . $name,
	  subname($self->name . '::' . $name, $code));
    # tail-call it this way, because add_symbol uses "caller"
    goto &{ $self->can('add_symbol') };
}

# create a package with specified parents and return an object for it

sub make_package
{
    my ($self,$pkgname,@parents) = @_;
    eval "package $pkgname; our \@ISA; push \@ISA, \@parents; 1"
	or confess "$@";
    return $self->new($pkgname);
}

#----------------------------------------------------------------------------

=head1 NAME

    Net::PGSQL::Protocol3::BackendMsg - messages received from backend

=head1 FUNCTIONS

=over

=item type

Returns the packet type as a string (e.g. 'DataRow')

=item dump

Returns a string representation for debugging

=item FIELDNAME

Message types with data have accessor functions to return the field values.

=back

=head1 NOTABLE SUBTYPES

=over

=cut

package Net::PGSQL::Protocol3::BackendMsg;

use strict;
use Scalar::Util qw(reftype);
use List::MoreUtils qw(part);

# given $pkg, @keys we define the constructor according to style:
#  % - plain hash, the message has a fixed set of named fields
#  %@ - hash and array, the message has 0 or more fixed fields and one list
#  %% - hash of hashes, the message has one named field which is a dynamic hash
#  @% - hash of arrays, the message contains a list of items each of which
#       has a fixed list of fields

sub _def_new
{
    my ($pkg, $style, @keys) = @_;
    my $akey = ($style eq '%@') ? (pop @keys) : undef;
    my $hkey = ($style eq '%%') ? (pop @keys) : undef;

    if ($style eq '')
    {
	$pkg->defun(
	    'new',
	    sub {
		my $v = "";
		return bless \$v,shift;
	    });
    }
    elsif ($style ne '@%')
    {
	$pkg->defun(
	    'new',
	    sub {
		my $self = bless {},shift;
		@{$self}{@keys} = splice(@_,0,scalar @keys) if @keys;
		${$self}{$akey} = [ @_ ] if defined $akey;
		${$self}{$hkey} = { @_ } if defined $hkey;
		return $self;
	    });
    }
    else
    {
	$pkg->defun(
	    'new',
	    sub {
		my $self = bless {},shift;
		my $i = 0;
		@{$self}{@keys} = part { $i++ % @keys } @_;
		$$self{_count} = scalar @{$$self{$keys[0]}};
		return $self;
	    });
	$pkg->defun('count', sub { shift->{_count} });
    }
}

BEGIN {

    my %be_msgtypes = (
	'R' => [ "Authentication",       "Na*",      undef ],
	'K' => [ "BackendKeyData",       "NN",       '%',  qw(pid key) ],
	'2' => [ "BindComplete",         "",         "" ],
	'3' => [ "CloseComplete",        "",         "" ],
	'C' => [ "CommandComplete",      "Z*",       '%',  qw(tag) ],
	'd' => [ "CopyData",             "a*",       '%',  qw(data) ],
	'c' => [ "CopyDone",             "",         "" ],
	'G' => [ "CopyInResponse",       "C n/n",    '%@', qw(format columnformats) ],
	'H' => [ "CopyOutResponse",      "C n/n",    '%@', qw(format columnformats) ],
	'D' => [ "DataRow",              "na*",      '%',  qw(count _data) ],      # "n/(N/a)" but nulls interfere
	'I' => [ "EmptyQueryResponse",   "",         "" ],
	'E' => [ "ErrorResponse",        "(a1 Z*)*", '%%', qw(values) ],
	'V' => [ "FunctionCallResponse", "N! a*",    '%',  qw(length value) ],
	'n' => [ "NoData",               "",         "" ],
	'N' => [ "NoticeResponse",       "(a1 Z*)*", '%%', qw(values) ],
	'A' => [ "NotificationResponse", "NZ*Z*",    '%',  qw(pid name data) ],
	't' => [ "ParameterDescription", "n/N",      '%@', qw(typeids) ],
	'S' => [ "ParameterStatus",      "Z*Z*",     '%',  qw(param value) ],
	'1' => [ "ParseComplete",        "",         "" ],
	's' => [ "PortalSuspended",      "",         "" ],
	'Z' => [ "ReadyForQuery",        "a1",       '%',  qw(trans) ],
	'T' => [ "RowDescription",       "n/(Z* N n! N n! N! n)",
	         '@%', qw(colname tableoid attnum coltype typlen typmod format) ],
	);

    my $pkg_base_name = __PACKAGE__;
    my $pfx = $pkg_base_name . "::";

    for my $_pkgi (values %be_msgtypes)
    {
	my ($name,$templ,$type,@okeys) = @$_pkgi;
	my $pkgname = $pfx . $name;
	my $pkg = Net::PGSQL::PackageMgr->make_package($pkgname, __PACKAGE__);
	next unless defined $type;
	_def_new($pkg, $type, @okeys);
	$pkg->defun('type', sub { $name });
	$pkg->defun('_keys', sub { @okeys });
	for my $key (@okeys)
	{
	    if ($type eq '@%')
	    {
		my $k = $key;
		$pkg->defun($key, sub { (1 < @_) ? $_[0]->{$k}[$_[1]] : $_[0]->{$k} });
	    }
	    else
	    {
		my $k = $key;
		$pkg->defun($key, sub { $_[0]->{$k} });
	    }
	}
    }

    sub new
    {
	my ($self,$msgtype,$data) = @_;
	my $info = $be_msgtypes{$msgtype};
	return undef unless defined $info;
	my ($name,$templ) = @$info;
	$name = __PACKAGE__ . "::$name";
	return $name->new(unpack($templ,$data));
    }
}

sub _dumpfields
{
    my $self = shift;
    map {
	my $v = $$self{$_};
	ref($v) eq 'ARRAY' ? '['.join(' ',@$v).']' :
	    ref($v) eq 'HASH' ? '{ '.join(', ', map { "$_ => ".$v->{$_} } keys %$v).' }' : $v
    } @_;
}

sub dump
{
    my $self = shift;
    my $name = $self->type;
    return $name if (reftype($self) eq 'SCALAR');
    my @keys = $self->_keys;
    return "${name}(@{[ @keys ]}) = (@{[ join ' ', $self->_dumpfields(@keys) ]})";
}


package Net::PGSQL::Protocol3::BackendMsg::Authentication;

use strict;

BEGIN {

    my %be_auth_msgtypes = (
	0 => [ "Ok", "" ],
	2 => [ "KerberosV5",        "" ],
	3 => [ "CleartextPassword", "" ],
	4 => [ "CryptPassword",     "a2", qw(salt) ],
	5 => [ "MD5Password",       "a4", qw(salt) ],
	6 => [ "SCMCredential",     "" ],
	7 => [ "GSS",               "" ],
	8 => [ "GSSContinue",       "a*", qw(data) ],
	9 => [ "SSPI",              "" ],
    );

    my $pkg_base_name = __PACKAGE__;
    my $pfx = $pkg_base_name . "::";

    for my $_pkgi (values %be_auth_msgtypes)
    {
	my ($name,undef,@keys) = @$_pkgi;
	my $pkgname = $pfx . $name;
	my $pkg = Net::PGSQL::PackageMgr->make_package($pkgname, __PACKAGE__);
	$pkg->defun('new',
		    sub {
			my $self = bless {},shift;
			@{$self}{@keys} = @_ if @keys;
			return $self;
		    });
	$pkg->defun('type', sub { "Authentication$name" });
	$pkg->defun('_keys', sub { @keys });
	for my $key (@keys)
	{
	    my $k = $key;
	    $pkg->defun($key, sub { $_[0]->{$k} });
	}
    }

    sub new
    {
	my ($self,$num,$data) = @_;
	my $info = $be_auth_msgtypes{$num};
	return bless { data => $data },$self unless $info;
	my ($type,$fmt) = @$info;
	$type = __PACKAGE__ . "::$type";
	return $type->new(unpack($fmt,$data));
    }
}


package Net::PGSQL::Protocol3::BackendMsg::FunctionCallResponse;

use strict;

sub isnull
{
    my $self = shift;
    $$self{length} < 0;
}


=item DataRow

DataRow has an accessor function C<data> which returns a reference to
a tied array of fields (to avoid wasting excess time and memory by
expanding to hashes).

=cut

package Net::PGSQL::Protocol3::BackendMsg::DataRow;

use strict;

sub _parse
{
    my $self = shift;
    my $rawdata = $$self{_data};
    my $pos = 0;
    my $count = $$self{count};
    my @pos = (undef) x $count;
    for my $i (0..$#pos)
    {
	my $flen = unpack("\@$pos N!",$rawdata);
	$pos[$i] = $pos, $pos += $flen
	    if $flen >= 0;
	$pos += 4;
    }
    $$self{_pos} = \@pos;
}

sub TIEARRAY
{
    my ($class,$obj) = @_;
    $obj->_parse unless exists $$obj{_pos};
    return $obj;
}

sub FETCH
{
    my ($self,$i) = @_;
    my $pos = $$self{_pos}->[$i];
    return undef unless defined $pos;
    return unpack("\@$pos N/a", $$self{_data});
}

sub FETCHSIZE
{
    my $self = shift;
    return $$self{count};
}

sub EXISTS
{
    1;
}

sub STORE     { die "modification of DataRow not permitted" }
sub STORESIZE { die "modification of DataRow not permitted" }
sub POP       { die "modification of DataRow not permitted" }
sub PUSH      { die "modification of DataRow not permitted" }
sub SHIFT     { die "modification of DataRow not permitted" }
sub UNSHIFT   { die "modification of DataRow not permitted" }
sub SPLICE    { die "modification of DataRow not permitted" }
sub DELETE    { die "modification of DataRow not permitted" }
sub CLEAR     { die "modification of DataRow not permitted" }

sub data
{
    my $self = shift;
    my @a;
    tie @a, ref($self), $self;
    return \@a;
}

sub dump
{
    my $self = shift;
    my $name = $self->type;
    my $dat = $self->data;
    return "${name}(count data) = (@{[ join ' ', $self->{count}, map { defined($_) ? $_ : '(undef)' } @$dat ]})";
}

=back

=cut

#----------------------------------------------------------------------------

=head1 NAME

    Net::PGSQL::Protocol3::FrontendMsg - messages sent by frontend

=head1 FUNCTIONS

=over

=item new ARGS

Constructs the packet but does not enqueue it. The methods in
Net::PGSQL::Protocol3 to create and enqueue the packet are usually
preferred.

=back

=head1 NOTABLE SUBTYPES

=over

=cut

package Net::PGSQL::Protocol3::FrontendMsg;

use strict;

BEGIN {

    my %fe_msgtypes = (
	"StartupRequest"  => undef,
	"SSLRequest"      => undef,
	"CancelRequest"   => undef,
	"Bind"            => [ 'B', undef ],
	"Close"           => [ 'C', "a1Z*" ],
	"CopyData"        => [ 'd', "a*" ],
	"CopyDone"        => [ 'c', "" ],
	"CopyFail"        => [ 'f', "Z*" ],
	"Describe"        => [ 'D', "a1Z*" ],
	"Execute"         => [ 'E', "Z*N" ],
	"Flush"           => [ 'H', "", 1 ],
	"FunctionCall"    => [ 'F', undef ],
	"Parse"           => [ 'P', undef ],
	"PasswordMessage" => [ 'p', "a*" ],
	"Query"           => [ 'Q', "Z*", 1 ],
	"Sync"            => [ 'S', "", 1 ],
	"Terminate"       => [ 'X', "", 1 ]
	);

    my $pkg_base_name = __PACKAGE__;
    my $pfx = $pkg_base_name . '::';
    my $rpkg = Net::PGSQL::PackageMgr->new("Net::PGSQL::Protocol3");

    for my $k (keys %fe_msgtypes)
    {
	my $name = $k;
	my $v = $fe_msgtypes{$name};
	my $pkgname = $pfx . $name;
	my $pkg = Net::PGSQL::PackageMgr->make_package($pkgname, __PACKAGE__);
	$pkg->defun('type', sub { $name });
	next unless defined($v);

	{
	    my ($type,$templ,$aflush) = @$v;
	    defined($templ)
		and $pkg->defun('new', sub { shift->_init($type, pack($templ, @_)) });
	    defined($aflush)
		and $aflush
		and $pkg->defun('_flush', sub { 1 });
	}

	$rpkg->defun($name,
		     sub { return shift->enqueue("${pfx}${name}"->new(@_)) });
    }
}

sub len
{
    my $self = shift;
    return length($$self);
}

sub data
{
    my $self = shift;
    return $$self;
}

sub _init
{
    my ($self,$type,$msg) = @_;
    $msg = pack("a1Na*", $type, length($msg)+4, $msg);
    return bless \$msg,$self;
}

sub _init_notype
{
    my ($self,$msg) = @_;
    $msg = pack("Na*", length($msg)+4, $msg);
    return bless \$msg,$self;
}

sub _flush
{
    0;
}

sub dump
{
    my $self = shift;
    my $name = $self->type;
    return $name . " = " . unpack("H*",$$self);
}


package Net::PGSQL::Protocol3::FrontendMsg::StartupRequest;

use strict;

sub new
{
    my ($self) = shift;
    return $self->_init_notype(pack("N(Z*Z*)*x", 196608, @_));
}

sub _flush { 1 }


package Net::PGSQL::Protocol3::FrontendMsg::SSLRequest;

use strict;

sub new
{
    my ($self) = @_;
    return $self->_init_notype(pack("N", 80877103));
}

sub _flush { 1 }


package Net::PGSQL::Protocol3::FrontendMsg::CancelRequest;

use strict;

sub new
{
    my ($self,$pid,$key) = @_;
    return $self->_init_notype(pack("NNN", 80877102, $pid, $key));
}

sub _flush { 1 }


=item Bind PORTAL STATEMENT PFMTS PVALUES RFMTS

C<PORTAL> and C<STATEMENT> are strings. C<PFMTS> is an arrayref or
undef, giving the parameter format codes (0=text, 1=binary).
C<PVALUES> is an arrayref or undef with the parameter values.
C<RFMTS> is an arrayref or undef, giving result column format codes.

=cut

package Net::PGSQL::Protocol3::FrontendMsg::Bind;

use strict;

sub new
{
    my $self = shift;
    my ($portal,$statement,$pformats,$pvalues,$rformats) = @_;
    return $self->_init('B', pack("Z*Z*a*a*a*",
				  defined($portal) ? $portal : "",
				  $statement,
				  pack("n/n*", $pformats ? @$pformats : ()),
				  pack("n/(a*)*",
				       map { defined $_
						 ? pack("N/a*",$_)
						 : pack("N",0xFFFFFFFF) }
				       $pvalues ? @$pvalues : ()),
				  pack("n/n*", $rformats ? @$rformats : ())));
}


package Net::PGSQL::Protocol3::FrontendMsg::FunctionCall;

use strict;

sub new
{
    my $self = shift;
    my ($oid,$pformats,$pvalues,$rformat) = @_;
    return $self->_init('F', pack("Na*a*n",
				  $oid,
				  pack("n/n*", $pformats ? @$pformats : ()),
				  pack("n/(a*)*",
				       map { defined $_
						 ? pack("N/a*",$_)
						 : pack("N",0xFFFFFFFF) }
				       $pvalues ? @$pvalues : ()),
				  $rformat));
}


=item Parse STATEMENT QUERY PTYPES...

C<STATEMENT> is the statement name as a string. C<QUERY> is the query.
C<PTYPES> is the list of parameter type oids if specified.

=cut

package Net::PGSQL::Protocol3::FrontendMsg::Parse;

use strict;

sub new
{
    my $self = shift;
    my ($statement,$query,@ptypes) = @_;
    return $self->_init('P', pack("Z*Z*n/N*",
				  $statement,
				  $query,
				  @ptypes));
}
			

# END

=back

=cut

1;

__END__

