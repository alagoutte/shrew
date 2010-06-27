
/*
 * Copyright (c) 2007
 *      Shrew Soft Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Redistributions in any form must be accompanied by information on
 *    how to obtain complete source code for the software and any
 *    accompanying software that uses the software.  The source code
 *    must either be included in the distribution or be available for no
 *    more than the cost of distribution plus a nominal fee, and must be
 *    freely redistributable under reasonable conditions.  For an
 *    executable file, complete source code means the source code for all
 *    modules it contains.  It does not include source code for modules or
 *    files that typically accompany the major components of the operating
 *    system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED BY SHREW SOFT INC ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR
 * NON-INFRINGEMENT, ARE DISCLAIMED.  IN NO EVENT SHALL SHREW SOFT INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * AUTHOR : Matthew Grooms
 *          mgrooms@shrew.net
 *
 */

#include "qikea.h"

bool _qikeaTopology::verify()
{
	QString Address = lineEditAddress->text();
	Address = Address.replace( ' ', "" );

	QString Netmask = lineEditNetmask->text();
	Netmask = Netmask.replace( ' ', "" );

	in_addr_t addr = ntohl( inet_addr( Address.toAscii() ) );
	in_addr_t mask = ntohl( inet_addr( Netmask.toAscii() ) );

	// verify the netmask

	if( ( mask != 0 ) && ( mask != ( in_addr_t ) ~0 ) )
	{
		long count = 31;
		long bitset = 31;
		long bitclr = 0;

		while( count >= 0 )
		{
			if( ( mask >> count ) & 1 )
				bitset = count;
			else
				bitclr = count;

			if( bitclr > bitset )
			{
				// error

				QMessageBox m;

				m.critical( this,
					"Topology Entry Error",
					"The network mask you have specified is invalid.",
					QMessageBox::Ok,
					QMessageBox::NoButton,
					QMessageBox::NoButton );

				return false;
			}

			count--;
		}
	}

	// verify the address

	if( addr & ~mask )
	{
		// warning

		QMessageBox m;

		m.warning( this,
			"Topology Entry Warning",
			"The network address is not valid for the given network mask.\n"
			"An acceptable value has been substituted.",
			QMessageBox::Ok,
			QMessageBox::NoButton,
			QMessageBox::NoButton );

		in_addr inaddr;
		inaddr.s_addr = htonl( addr & mask );

		lineEditAddress->setText( inet_ntoa( inaddr ) );

		return false;
	}

	// call the dialog accept function

	accept();

	return true;
}
