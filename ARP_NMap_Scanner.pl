#!/usr/bin/env perl
#===============================================================================
#
#         FILE: SSmith_FinalProject.pl
#
#        USAGE: ./SSmith_FinalProject.pl  [network adapter]
#
#  DESCRIPTION: Script that uses ARP requests to discover live hosts on the 
#  network. After discovery Nmap is used to scan each IP Address, returning a 
#  list of open ports and services.
#
#      OPTIONS: Network adapter passed as argument
# REQUIREMENTS: Modules -> Net::ARP
# 						   Net::Frame::Dump::Online
# 						   Net::Frame::Simple
# 						   Net::Netmask
# 						   Nmap::Scanner => Requires alteration & forced install!
#         BUGS: ---
#        NOTES: ---
#       AUTHOR: Sean Smith (Student), seasmit2@uat.edu
# ORGANIZATION: NTS370
#      VERSION: 1.0
#      CREATED: 07/09/2018 07:47:16 AM
#     REVISION: ---
#===============================================================================

use strict;
use warnings;
use utf8;

#-------------------------------------------------------------------------------
#  State which modules are going to be used
#-------------------------------------------------------------------------------
use Net::ARP;
use Net::Frame::Dump::Online;
use Net::Frame::Simple;
use Net::Netmask;
use Nmap::Scanner;

#-------------------------------------------------------------------------------
#  Define variables
#-------------------------------------------------------------------------------
my $red = "\e[1;31m[+]\e[0m";                           # Red text color
my $green = "\e[1;32m[+]\e[0m";                         # Green text color
my @Found_IPs = ();

my $Network_Adapter = $ARGV[0];
my $IF_Info = `ifconfig $Network_Adapter`;      # Save output of ifconfig command

# User regex matching to extract the local IP Address
$IF_Info =~ m/.*inet\s(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/;
my $IP_Address = $1;

# Use regex matching to extract the Netmask
$IF_Info =~ m/.*netmask\s(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/;
my $Netmask = $1;

# Use regex matching to extract the MAC Address
$IF_Info =~ m/.*ether\s([\d\D]{2}:[\d\D]{2}:[\d\D]{2}:[\d\D]{2}:[\d\D]{2}:[\d\D]{2})/;
my $Mac_Address = $1;

#-------------------------------------------------------------------------------
#  Get User input for some variables
#-------------------------------------------------------------------------------
print ("What ports would you like to scan?: ");
my $ports_to_scan = <STDIN>;
chomp ($ports_to_scan);

#-------------------------------------------------------------------------------
#  Create a Net::Netmask Object
#-------------------------------------------------------------------------------
my $Network = Net::Netmask->new($IP_Address, $Netmask);
my $Gateway = $Network -> base();               # Obtain base address of network

#-------------------------------------------------------------------------------
#  Create Nmap::Scanner object
#-------------------------------------------------------------------------------
my $scanner = Nmap::Scanner -> new();
$scanner -> add_scan_port($ports_to_scan);
$scanner -> tcp_syn_scan();
$scanner -> no_ping();
$scanner -> version_scan(4);

#-------------------------------------------------------------------------------
#  Print a quick status message displaying the now known information
#-------------------------------------------------------------------------------
printf ("#=======================================================#\n");
printf ("#    Network Interface: %s\n", $Network_Adapter);
printf ("#     Local IP Address: %s\n", $IP_Address);
printf ("#         Network Mask: %s\n", $Netmask);
printf ("#    Local MAC Address: %s\n", $Mac_Address);
printf ("#  Ports to be Scanned: %s\n", $ports_to_scan);

#-------------------------------------------------------------------------------
#  Create a Net::Frame::Dump::Online packet capture object
#-------------------------------------------------------------------------------
my $Pcap = Net::Frame::Dump::Online->new(
	dev => $Network_Adapter,
	filter => 'arp and dst host '.$IP_Address,
	promisc => 0,
	unlinkOnStop => 1,
	timeoutOnNext => 30);

#-------------------------------------------------------------------------------
#  Start packet capture and send ARP requests to all host addresses on network
#-------------------------------------------------------------------------------
printf ("$red Starting Packet Capture\n");
$Pcap -> start;
printf ("\t$green Packet Capture Started Successfully\n");
printf ("$red Sending ARP requests now\n");

my $Requests = 0;
for my $host ($Network -> enumerate) {          # Enumerate Network Using Net::Netmask
	Net::ARP::send_packet(                      # Send arp packet
	$Network_Adapter,                           # Set Network Adapter
	$IP_Address,                                # Set Soruce IP
	$host,                                      # Set Dst IP
	$Mac_Address,                               # Set Source MAC
	"ff:ff:ff:ff:ff:ff",                        # Set Dst MAC to Broadcast
	"request");
	
	$Requests++;
}

printf ("\t$green %s ARP requests sent!\n", $Requests);
#-------------------------------------------------------------------------------
#  Pasrse the packet capture and extract IP addresses
#-------------------------------------------------------------------------------
until ($Pcap -> timeout) {
	if (my $next = $Pcap -> next) {
		my $Frame = Net::Frame::Simple -> newFromDump($next);
		my $Found_IP = $Frame -> ref -> {ARP} -> srcIp;
		
		my %FoundHosts = map {$_ => 1} @Found_IPs;
		if(exists($FoundHosts{$Found_IP})) {
			next;
		}

		push(@Found_IPs, $Found_IP);
		printf ("$red Found Host with IP: %s\n", $Found_IP);
		print ("\t$green Host added to scan list\n\n");
		$scanner -> add_target($Found_IP);
	}
}

print ("$red Packet capture timeout reached, Starting Nmap scan\n");
print ("\t$green This may take a while depending on the number of hosts and ports to be scanned\n");
#-------------------------------------------------------------------------------
#  Run Nmap Scan and return the open ports and service if available
#-------------------------------------------------------------------------------
my $Nmap_Results = $scanner -> scan();
my $host_list = $Nmap_Results -> get_host_list();

while (my $host = $host_list -> get_next()){
	no warnings;
	my $address = join(' , ', map {$_ -> addr()} $host -> addresses());
	printf ("\n[+] Host IP,MAC Address: %s\n", $address);
	print ("\tOpen Port\tService\n");

	my $ports = $host -> get_port_list();
	while (my $p = $ports -> get_next()){
		if ($p -> {state} eq "closed" || $p -> {state} eq "filtered"){
			next;
		}
		my $service = join('', map {$_ -> product()} $p -> service());
		printf ("\t$green %s\t\t%s\n", $p -> {portid}, $service);
	}
}

#-------------------------------------------------------------------------------
#  All Done!
#-------------------------------------------------------------------------------
                                                                                      
                                                                                      
print("\nDDDDDDDDDDDDD             OOOOOOOOO     NNNNNNNN        NNNNNNNNEEEEEEEEEEEEEEEEEEEEEE\n");
print("D::::::::::::DDD        OO:::::::::OO   N:::::::N       N::::::NE::::::::::::::::::::E\n");
print("D:::::::::::::::DD    OO:::::::::::::OO N::::::::N      N::::::NE::::::::::::::::::::E\n");
print("DDD:::::DDDDD:::::D  O:::::::OOO:::::::ON:::::::::N     N::::::NEE::::::EEEEEEEEE::::E\n");
print("  D:::::D    D:::::D O::::::O   O::::::ON::::::::::N    N::::::N  E:::::E       EEEEEE\n");
print("  D:::::D     D:::::DO:::::O     O:::::ON:::::::::::N   N::::::N  E:::::E             \n");
print("  D:::::D     D:::::DO:::::O     O:::::ON:::::::N::::N  N::::::N  E::::::EEEEEEEEEE   \n");
print("  D:::::D     D:::::DO:::::O     O:::::ON::::::N N::::N N::::::N  E:::::::::::::::E   \n");
print("  D:::::D     D:::::DO:::::O     O:::::ON::::::N  N::::N:::::::N  E:::::::::::::::E   \n");
print("  D:::::D     D:::::DO:::::O     O:::::ON::::::N   N:::::::::::N  E::::::EEEEEEEEEE   \n");
print("  D:::::D     D:::::DO:::::O     O:::::ON::::::N    N::::::::::N  E:::::E             \n");
print("  D:::::D    D:::::D O::::::O   O::::::ON::::::N     N:::::::::N  E:::::E       EEEEEE\n");
print("DDD:::::DDDDD:::::D  O:::::::OOO:::::::ON::::::N      N::::::::NEE::::::EEEEEEEE:::::E\n");
print("D:::::::::::::::DD    OO:::::::::::::OO N::::::N       N:::::::NE::::::::::::::::::::E\n");
print("D::::::::::::DDD        OO:::::::::OO   N::::::N        N::::::NE::::::::::::::::::::E\n");
print("DDDDDDDDDDDDD             OOOOOOOOO     NNNNNNNN         NNNNNNNEEEEEEEEEEEEEEEEEEEEEE\n");
                                                                                      
