================================================================================
ABOUT
================================================================================

This software distribution contains the Shrew Soft Inc Internet Key exchange
daemon and IPsec VPN client front end applications. All included source code
and supporting materials are covered under a liberal open source license.
Please see the LICENSE.TXT file for more details. The source code is organized
as several components that work together to facilitate IPsec communications.

iked - Internet Key Exchange Daemon

This component implements the IKE protocol version 1 for IPv4 networks and is
very similar to the IPsec tools racoon daemon. It supports an extensive feature
set that includes NAT-Traversal, Dead Peer Detection, Mode Config for
centralized client configuration and management, dynamic security policy
configuration and dynamic route management.

The daemon supports two different modes of operation depending on how it is
configured. This first mode of operation allows it to interact with Client
Front end applications to facilitate Client to Gateway remote access. The other
mode allows it to facilitate site to site IPsec key exchange provide advanced
client gateway functionality. At this time, is recommended that the daemon only
be used in client mode due to lack of adequate testing. If you need to install
a VPN Client Gateway, please use the IPsec Tools racoon daemon. Version 0.7 or
later is highly recommended.

ikec - VPN Client Connect Application

This component provides a console based user interface that represents a
connection instance for a remote site. It allows a user to connect or
disconnect, enter user login credentials and view the status of the remote
access connection.

qikea - VPN Access Manager Application ( optional )

This component provides a GUI user interface for managing remote site
configurations. It is also used to launch a VPN Client Connect instance for a
given remote site.

qikec - VPN Client Connect Application ( optional )

This component provides a GUI user interface that represents a connection
instance for a remote site. It allows a user to connect or disconnect, enter
user login credentials and view the status of the remote access connection.


================================================================================
REQUIREMENTS
================================================================================

This section describes the basic requirements used to compile this software. In
most cases, development versions of the dependencies will need to be installed.
These could be available as pre-compiled packages or compiled directly from
source.

Minimum
--------------------------------------------------------------------------------

c++ compiler
stock c libs
stock c includes
pthread support

lex or flex
libedit
bison >= 2.3
cmake >= 2.4
opsenssl >= 0.9.x

This software requires Bison version 2.3 or higher as it uses the new c++
parser model. The c++ model was introduced in version 2.1 but appears to be
incomplete.

Optional
--------------------------------------------------------------------------------

TrollTech QT >= 4.2
openldap >= 2.0

The Trolltech QT toolkit version 4.2.x or higher is also required if you plan
to build the QT client front end applications. The openldap support is only
useful if you plan to use iked to facilitate VPN client gateway connectivity
and require xauth support via an external LDAP database.


================================================================================
PLATFORM SUPPORT
================================================================================

The FreeBSD, NetBSD and several Linux operating systems are supported and have
been tested with this software. A free windows client is also available but
requires custom kernel support and additional software that is not covered
under an open source license. Please see the Shrew Soft Inc web site for more
details.

The only processor architectures that have been tested are i386 and amd64. It
may be that this software works with more exotic architectures such as powerpc
or sparc but no testing has been performed to confirm this. With the exception
of the Windows client, this software utilizes the native IPsec kernel support
which is bundled with all supported operating systems. Depending on your
platform, a custom kernel may need to compiled or additional kernel modules
may need to be loaded before it will operate correctly. Please see the specific
platform notes for more details.

FreeBSD
--------------------------------------------------------------------------------

FreeBSD version 6.2 RELEASE was used to test this software. You will need to
make sure your kernel has been built with IPsec support. Either the KAME IPsec
stack or the Fast IPsec stack is supported.

For example, to add support for Fast IPsec you could enable the following
options in your custom kernel configuration file ...

# IP Security
device          crypto
options         FAST_IPSEC

As of FreeBSD 6.2, NATT kernel support has not yet been committed to the main
line source. However, a high quality patch is available and has been tested
with this software. It can be obtained from the following url ...

http://ipsec-tools.sourceforge.net/freebsd6-natt.diff

Before this software can be compiled with NATT support, the patch must be
applied to your kernel. To apply the patch, you need to copy the file into
your /usr/src/sys directory and apply it using the following command ...

patch < freebsd6-natt.diff

To enable this support, include the additional option in your custom kernel
configuration file ...

options		IPSEC_NAT_T

You will then need to build and install the custom kernel and perform a
buildworld and installworld. Please see the FreeBSD handbook for more
information on compiling and installing a custom kernel and userland.

The following options are recommended when running the cmake configuration
for FreeBSD. Please see the OPTIONS section for more details.

cmake -DQTGUI=YES -DNATT=YES

NetBSD
--------------------------------------------------------------------------------

NetBSD version 3.1 was used to test this software. You will need to make sure
your kernel has been built with IPsec support.

For example, to include support for IPsec you could enable the following
options in your custom kernel configuration file ...

options         INET
options         IPSEC
options         IPSEC_ESP
options         IPSEC_NAT_T

Please see the NetBSD Documentation for more information on compiling and
installing a custom kernel.

The following options are recommended when running the cmake configuration
for NetBSD. Please see the OPTIONS section for more details.

cmake -DQTGUI=YES -DNATT=YES -DETCDIR=/etc

NetBSD also appears to require several environment variables to be set when
compiling and using the QT front end applications. For example, the following
lines were added to the users ~/.profie script when testing this software for
NetBSD ...

QTDIR=/usr/pkg/qt4
QMAKESPEC=netbsd-g++
PATH=${PATH}:${QTDIR}/bin
LD_LIBRARY_PATH=/usr/pkg/qt4/lib/:/usr/X11R6/lib

export PATH QTDIR QMAKESPEC LD_LIBRARY_PATH

Linux
--------------------------------------------------------------------------------

Beginning with linux version 2.6, native kernel support has been added for the
IPsec protocol suite. Both the Fedora Core 6 and Ubuntu 7.04 distributions were
tested and came preinstalled with both ESP and NAT-T support by default. If you
use another distribution, a custom kernel or additional modules may be be
required. Please see your distribution documentation for more details.

The following options are recommended when running the cmake configuration
for linux platforms. Please see the OPTIONS section for more details.

cmake -DCMAKE_INSTALL_PREFIX=/usr -DQTGUI=YES -DETCDIR=/etc -DNATT=YES

For 64 bit Linux systems, most distributions store native 64bit library files
in a unique path. The option for this is -LIBDIR=/usr/lib64 or the appropriate
directory path.

NOTE : It may also be necessary to add the KRNINC option to specify the kernel
header file path on older versions of Linux.

OSX
--------------------------------------------------------------------------------

Apple OSX provides native kernel support for the IPsec protocol suite. This
software was designed to support OSX version 10.8 and later. This software
can also be linked against a private Qt library build when gui components are
desired. When an install step is performed, a private copy of the Qt libs
will also be installed. All references to that library will be modified to
utilize the private library path.

The following options are recommended when running the cmake configuration
for OSX platforms. Please see the OPTIONS section for more details.

cmake -DQTGUI=YES -DNATT=YES -DCMAKE_INSTALL_PREFIX=/usr \
      -DQT_QMAKE_EXECUTABLE=[/qt/install/path]/bin/qmake

NOTE : Qt will still attempt to load plugin libraries from the original private
Qt install path. Since these libraries will have references to the original
Qt library framework paths ( not the copy ), the dynamic link loader may load
multiple versions of Qt libraries and cause the application to crash. It may
be necessary to move the private qt install path to a different location before
executing the compiled gui applications. For example:

mv /qt/install/path /qt/install/path.bak

================================================================================
COMPILING
================================================================================

The cmake build system is used to generate platform specific make files. To
configure the build, you simply run cmake in the base distribution directory
using any optional parameters you may require. For example: enter the following
to build and install the basic software ...

cmake [OPTIONS]
make
make install

================================================================================
OPTIONS
================================================================================

In addition to the standard CMake options such as CMAKE_INSTALL_PREFIX, a few
additional build parameters may be specified. Here is a brief list ...

DEBUG	Enable Debug Symbols
TESTS	Enable Library Tests Build
QTGUI	Enable Client QT GUI
NATT	Enable Nat Traversal Support
LDAP	Enable LDAP Authentication Support
ETCDIR	Custom etc configuration install path
BINDIR  Custim user bin install path
SBINDIR Custim user sbin install path
LIBDIR	Custom user lirbrary install path
MANDIR	Custom man page install path
KRNINC	Kernel include path

For example: enter the following to build and install the software with a few
common options enabled ...

cmake -DDEBUG=YES -DQTGUI=YES -DNATT=YES -DLDAP=YES
make
make install

================================================================================
USAGE
================================================================================

The main process that handles IKE negotiations is iked and must be run as root.
By default, it will detach itself from the terminal and execute as a daemon. To
force foreground operation, use the -F switch. A sample configuration file is
included in this distribution and will be installed in the etc system
configuration directory. The configuration should be suitable to allow for
client operation but can also be modified to allow for site to site or client
gateway operation as well. See the iked.conf man page for more details.

Once the iked process has been launched, the VPN Access Manager application
( qikea ) is used to build remote access client configurations and initiate
client connections. When the Access Manager GUI is used to initiate a client
connection, a VPN Connect application ( qikec ) process is created. This
process interacts with iked to initiate the connection. Alternately, a command
line version of the VPN Connect application ( ikec ) can be used to initiate a
connection. Please see the online documentation available at
http://www.shrew.net for more details.

================================================================================
EXPORTED CONFIGURATION FILES
================================================================================

A site configuration contains all the data required to connect to a site using
the VPN client tools. These configuration files can be exported or imported
using the VPN Access Manager application. The file format used to describe the
site configuration is a text ducument that contains one attribute per line with
one or more attribute values. The attribute type is denoted by a single 
charachter field followed by the attribute name field and then by a value. The
fields are separated using a colon charachter. For example, the following line
describes a string attribute names network-host with a value of 10.1.1.1

s:network-host:10.1.1.1

Attributes are denoted as one of three types.

s = String
n = Number
b = Binary ( bas64 encoded )

Multi valued strings are separated using a comma charachter and binary values
are base64 encoded. Here is a list of attributes currently supported.

s:network-host:<hostname>|<IP address>
n:network-ike-port:<IKE UDP port>
s:network-auto-mode:disable|pull|push|dhcp
s:client-iface:virtual|direct
n:client-addr-auto:0|1
s:client-ip-addr:<virtual IP address>
s:client-ip-mask:<virtual IP netmask>
n:network-mtu-size:<virtual MTU>
n:client-wins-used:0|1
n:client-wins-auto:0|1
s:client-wins-addr:<WINS server IP address list>
n:client-dns-used:0|1
n:client-dns-auto:0|1
s:client-dns-addr:<DNS server IP address list>
s:client-dns-suffix:<DNS default suffix>
n:client-splitdns-used:0|1
n:client-splitdns-auto:0|1
s:client-splitdns-list:<DNS split suffix list>
s:network-natt-mode:disable|enable|force-draft|force-rfc
s:network-frag-mode:disable|enable|force
n:network-dpd-enable:0|1
n:network-notify-enable:0|1
n:client-banner-enable:0|1
s:auth-method:hybrid-rsa-xauth|mutual-rsa-xauth|mutual-psk-xauth|mutual-rsa|mutual-psk
s:auth-server-cert:<path to server ca>
s:auth-client-cert:<path to client public cert>
s:auth-client-key:<path to client private key>
b:auth-mutual-psk:<mutual pre-shared key>
s:ident-client-type:asn1dn|keyid|fqdn|ufqdn|address
s:ident-client-data:<type specific value>
s:ident-server-type:asn1dn|keyid|fqdn|ufqdn|address
s:ident-server-data:<type specific value>
s:phase1-exchange:main|aggressive
s:phase1-cipher:auto|aes|blowfish|3des|cast|des
n:phase1-keylen:<key length> ( 0 = auto )
s:phase1-hash:auto|md5|sha1
n:phase1-dhgorup:1|2|5|14|15
n:phase1-life-secs:<life time>
n:phase1-life-kbytes:<life KBytes>
s:phase2-transform:auto|esp-aes|esp-blowfish|esp-3des|esp-cast|esp-des
n:phase2-keylen:<key length> ( 0 = auto )
s:phase2-hmac:auto|md5|sha1
n:phase2-pfsgroup:-1|0|1|2|5|14|15 ( -1 = disabled, 0 = auto )
n:phase2-life-secs:<life time>
n:phase2-life-kbytes:<life KBytes>
s:policy-level:auto|required|unique|shared
n:policy-nailed:0|1 ( persistent IPsec SAs )
n:policy-list-auto:0|1
s:policy-list-exclude:<address/netmask list>
s:policy-list-include:<address/netmask list>

NOTE : When a file is exported, the certificate and key file paths are modified
to only contain the unqualified filename. The actual file data is encoded as a
binary value. This allows the certificate information to be exported along with
other site configuration data. Here are the related attributes after export.

s:auth-server-cert:<server ca filename>
b:auth-server-cert-data:<server ca file contents>
s:auth-client-cert:<client public cert filename>
b:auth-client-cert-data:<client public cert file contents>
s:auth-client-key:<client private key filename>
b:auth-client-key-data:<client private key file contents>
