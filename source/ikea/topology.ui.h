/****************************************************************************
** ui.h extension file, included from the uic-generated form implementation.
**
** If you want to add, delete, or rename functions or slots, use
** Qt Designer to update this file, preserving your code.
**
** You should not define a constructor or destructor in this file.
** Instead, write your code in functions called init() and destroy().
** These will automatically be called by the form's constructor and
** destructor.
*****************************************************************************/

#include "ikea.h"


void topology::init()
{
        lineEditAddress->setInputMask( "00D . 00D . 00D . 00D" );
        lineEditAddress->setText( "0.0.0.0" );

        lineEditNetmask->setInputMask( "00D . 00D . 00D . 00D" );
        lineEditNetmask->setText( "0.0.0.0" );
}

void topology::TopologyAccept()
{
	QString Address = lineEditAddress->text();
	Address = Address.replace( ' ', "" );

	QString Netmask = lineEditNetmask->text();
	Netmask = Netmask.replace( ' ', "" );

	in_addr_t addr = ntohl( inet_addr( Address.ascii() ) );
	in_addr_t mask = ntohl( inet_addr( Netmask.ascii() ) );

	// verify the netmask

	if( ( mask != 0 ) && ( mask != ( in_addr_t ) ~0 ) )
	{
		long bitset = 0;
		long bitclr = 0;
		long count = 31;

		while( count >= 0 )
		{
			if( ( mask >> count ) & 1 )
				bitset = count;
			else
				bitclr = count;

			if( ( !bitset && !count ) || ( bitclr > bitset ) )
			{
				// error

				QMessageBox m;

				m.critical( this,
					"Topology Entry Error",
					"The network mask you have specified is invalid.",
					QMessageBox::Ok,
					QMessageBox::NoButton,
					QMessageBox::NoButton );

				return;
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

		return;
	}

	// call the dialog accept function

	accept();
}
