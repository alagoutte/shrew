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

ikea - VPN Access Manager Application ( optional )

This component provides a user interface for managing remote site
configurations. It is also used to launch a VPN Client Connect instance for a
given remote site.

ikec - VPN Access Manager Application ( optional )

This component provides a user interface that represents a connection instance
for a remote site. It allows a user to connect or disconnect, enter user login
credentials and view the status of the remote access connection.


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
bison >= 2.3
cmake >= 2.4
opsenssl >= 0.9.x

This software requires Bison version 2.3 or higher as it uses the new c++
parser model. The c++ model was introduced in version 2.1 but appears to be
incomplete.

Optional
--------------------------------------------------------------------------------

TrollTech QT >= 3.3 ( multithreaded version, qt-mt )
openldap >= 2.0

The Trolltech QT toolkit version 3.3.x or higher is also required if you plan
to build the QT client front end applications. Version 4.x has not been tested
and is not supported. The openldap support is only required if you plan to use
iked to facilitate VPN client gateway connectivity and require xauth support
via an external LDAP database.


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

QTDIR=/usr/pkg/qt3
QMAKESPEC=netbsd-g++
PATH=${PATH}:${QTDIR}/bin
LD_LIBRARY_PATH=/usr/pkg/qt3/lib/:/usr/X11R6/lib

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


================================================================================
COMPILING
================================================================================

The build system uses cmake to generate platform dependent make files. To
configure the build, you simply run cmake in the base distribution directory
using any optional parameters you may require. For example: enter the following
to build and install the basic software ...

cmake .
make
make install


================================================================================
OPTIONS
================================================================================

In addition to the standard CMake options such as CMAKE_INSTALL_PREFIX, a few
additional build parameters may be specified. Here is a brief list ...

DEBUG	Enable Debug Symbols
QTGUI	Enable Client QT GUI
NATT	Enable Nat Traversal Support
LDAP	Enable LDAP Authentication Support
ETCDIR	System etc configuration path
MANDIR	System man page path
SYSINC	System include path

For example: enter the following to build and install the software with all
options enabled ...

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

Once the iked process has been launched, the ikea application can be used to
build remote access client configurations and initiate sessions. See the online
documentation available at http://www.shrew.net for more details.
