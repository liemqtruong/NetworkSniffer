#!/usr/bin/perl
###########################################
# capture -- Gtk2 GUI observing the network
# Mike Schilli, 2004 (m@perlmeister.com)
###########################################
use warnings;
use strict;

use Gtk2 -init;
use Gtk2::GladeXML;
use Glib;
use Net::Pcap;
use NetPacket::IP;
use NetPacket::Ethernet;
use Socket;

our @IPS = ();
our %IPS = ();

die "You need to be root to run this.\n" if
    $> != 0;

    # Load GUI XML description
my $g = Gtk2::GladeXML->new(
    'capture.glade');

    # Child/Parent communication pipe
pipe READHANDLE,WRITEHANDLE or 
    die "Cannot open pipe";

    # Fork off a child
our $pid = fork();
die "failed to fork" unless defined $pid;

if($pid == 0) {
        # Child, never returns
    snooper(\*WRITEHANDLE);
}

    # Parent, init text window
my $buf = Gtk2::TextBuffer->new();
$buf->set_text("No activity yet.\n");

my $text = $g->get_widget('textview1');
$text->set_buffer($buf);

$g->signal_autoconnect_all(
    on_quit1_activate => sub {    
            # Stop snooper
        kill('KILL', $pid); 
        wait(); 
        Gtk2->main_quit; 
      },
    on_reset1_activate => sub { 
            # Reset display
        @IPS = ();
        %IPS = (); 
        $buf->set_text("");
      }
);

Glib::IO->add_watch(
    fileno(READHANDLE), 
    'in', \&watch_callback);

    # Enter main loop
Gtk2->main();

###########################################
sub watch_callback {
###########################################
    chomp(my $ip = <READHANDLE>);

        # Register IP if unknown
    unshift @IPS, $ip 
       unless exists $IPS{$ip};
    $IPS{$ip}++;

    my $text = "";

    $text .= "$_\n" for @IPS;

    $buf->set_text($text);

      # Return true to keep watch
    1; 
}

###########################################
sub snooper {
###########################################
    my($fd) = @_;

    my($err, $addr, $netmask);
    my $dev = Net::Pcap::lookupdev(\$err);
    
    if(Net::Pcap::lookupnet($dev, \$addr, 
                       \$netmask, \$err)) {
        die "lookupnet on $dev failed";
    }

    my $object = Net::Pcap::open_live($dev, 
                       1024, 1, -1, \$err);
    
    Net::Pcap::loop($object, -1, 
      \&snooper_callback, 
      [$fd, $addr, $netmask]);
}

###########################################
sub snooper_callback {
###########################################
    my($user_data, $header, $packet) = @_;

    my($fd, $addr, $netmask) = @$user_data;

    my $edata = 
       NetPacket::Ethernet::strip($packet);

    my $ip = NetPacket::IP->decode($edata);

    if((inet_aton($ip->{src_ip}) & 
        pack('N', $netmask)) eq 
          pack('N', $addr)) {
        syswrite($fd, "$ip->{src_ip}\n");
    }
}