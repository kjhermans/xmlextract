#!/usr/bin/perl

use strict;

my $file = shift @ARGV;
my $arg = shift @ARGV;
my $debug;
if ($arg eq '-d') {
  $debug = 1;
}
my %flows;

use File::PCAP::Reader;
use NetPacket::Ethernet qw(:types ETH_TYPE_IP);
use NetPacket::IP;
use NetPacket::UDP;
use NetPacket::TCP;
use XML::LibXML '1.70';

my $fpr = File::PCAP::Reader->new($file);
my $gh = $fpr->global_header();
while (my $np = $fpr->next_packet()) {
  my $buf = $np->{buf};
  my $eth = NetPacket::Ethernet->decode($buf);
  if ($eth->{type} eq ETH_TYPE_IP) {
    my $ip = NetPacket::IP->decode($eth->{data});
    if ($debug) {
      use Data::HexDump;
      print STDERR "$ip->{src_ip} -> $ip->{dest_ip} $ip->{proto}:\n";
      print STDERR HexDump($ip->{data});
    }
    if ($ip->{proto} eq 6) {
      my $tcp = NetPacket::TCP->decode($ip->{data});
      examine_data($np, $ip, $tcp);
    } elsif ($ip->{proto} eq 17) {
      my $udp = NetPacket::UDP->decode($ip->{data});
      examine_data($np, $ip, $udp);
    }
  }
}

sub examine_data
{
  my ($cap, $ip, $l3) = @_;
  my $flowkey = join(',', ($ip->{src_ip}, $l3->{src_port}));
  my $buf = $flows{$flowkey};
  if (!defined($buf)) {
    $buf = '';
    print STDERR "New flow $ip->{src_ip}:$l3->{src_port}\n";
  }
  my $data = $l3->{data};

  $buf .= $data;
  while (1) {
    $buf =~ s/^[^<]*//;
    $buf =~ /^(<\?xml.*?\?>\s*)?<([_a-zA-Z][_0-9a-zA-Z]*)/ || last;
    my $tag = $2;
    if ($buf =~ /^(<\?xml.*?\?>\s*)?(<$tag.*?<\/$tag>)/s
        || $buf =~ /^(<\?xml.*?\?>\s*)?(<$tag.*?\/>)/s)
    {
      my $potxml = "$1$2";
      my $parser = XML::LibXML->new();
      my $dom = eval { $parser->load_xml( string => $potxml ); };
      if ($parser) {
        $buf = substr($buf, length($potxml));
        print "At $cap->{ts_sec}.$cap->{ts_usec} " .
              "from $ip->{src_ip}:$l3->{src_port} -> " .
              "$ip->{dest_ip}:$l3->{dest_port}\n";
        my $beauty = $dom->serialize(1);
        $beauty =~ s/\n/\n  /g;
        print "  " . $beauty . "\n\n";
      } else {
        print STDERR "Error $@\n";
      }
    } else {
      last;
    }
  }
  $flows{$flowkey} = $buf;
}

1;
