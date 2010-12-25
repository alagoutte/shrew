
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

#include "qikec.h"

void _qikecRoot::customEvent( QEvent * e )
{
	if( e->type() == EVENT_STATUS )
	{
		StatusEvent * event = ( StatusEvent * ) e;

		switch( event->status )
		{
			case STATUS_WARN:

				textBrowserStatus->setTextColor( QColor( 192, 128, 0 ) );

				break;

			case STATUS_FAIL:

				textBrowserStatus->setTextColor( QColor( 128, 0, 0 ) );

				break;

			default:

				textBrowserStatus->setTextColor( QColor( 0, 0, 0 ) );
		}

		switch( event->status )
		{
			case STATUS_BANNER:
			{
				qikecBanner b( this );
				b.textBrowserMOTD->setText( event->text );
				b.exec();

				break;
			}

			case STATUS_DISCONNECTED:
				textLabelStatusValue->setText( "Disconnected" );
				lineEditUsername->setEnabled( true );
				lineEditPassword->setEnabled( true );
				pushButtonConnect->setEnabled( true );
				pushButtonConnect->setText( "Connect" );
				pushButtonExit->setEnabled( true );
				pushButtonExit->setText( "Exit" );
				textBrowserStatus->insertPlainText( "tunnel disabled\n" );
				break;

			case STATUS_CONNECTING:
				textLabelStatusValue->setText( "Connecting" );
				lineEditUsername->setEnabled( false );
				lineEditPassword->setEnabled( false );
				pushButtonConnect->setEnabled( false );
				pushButtonConnect->setText( "Connect" );
				pushButtonExit->setEnabled( true );
				pushButtonExit->setText( "Cancel" );
				textBrowserStatus->insertPlainText( "bringing up tunnel ...\n" );
				break;

			case STATUS_CONNECTED:
				textLabelStatusValue->setText( "Connected" );
				pushButtonConnect->setEnabled( true );
				pushButtonConnect->setText( "Disconnect" );
				pushButtonExit->setEnabled( false );
				pushButtonExit->setText( "Exit" );
				textBrowserStatus->insertPlainText( "tunnel enabled\n" );
				break;

			case STATUS_DISCONNECTING:
				textLabelStatusValue->setText( "Disconnecting" );
				pushButtonConnect->setEnabled( false );
				pushButtonConnect->setText( "Disconnect" );
				pushButtonExit->setEnabled( false );
				pushButtonExit->setText( "Exit" );
				textBrowserStatus->insertPlainText( "bringing down tunnel ...\n" );
				break;

			case STATUS_INFO:
			case STATUS_WARN:
			case STATUS_FAIL:
				textBrowserStatus->insertPlainText( event->text );
				break;

			default:

				textBrowserStatus->insertPlainText( "!!! unknown status message !!!\n" );
		}

		textBrowserStatus->moveCursor( QTextCursor::End );
	}

	if( e->type() == EVENT_STATS )
	{
		StatsEvent * event = ( StatsEvent * ) e;

		QString n;

		n.setNum( event->stats.sa_good );
		textLabelEstablishedValue->setText( n );

		n.setNum( event->stats.sa_dead );
		textLabelExpiredValue->setText( n );

		n.setNum( event->stats.sa_fail );
		textLabelFailedValue->setText( n );

		textLabelRemoteValue->setText( inet_ntoa( event->stats.peer.saddr4.sin_addr ) );

		switch( event->stats.natt )
		{
			case IPSEC_NATT_NONE:
				textLabelTransportValue->setText( "IKE | ESP" );
				break;

			case IPSEC_NATT_CISCO:
				textLabelTransportValue->setText( "IKE | CISCO-UDP / ESP" );
				break;

			case IPSEC_NATT_V00:
				textLabelTransportValue->setText( "NAT-T v00 / IKE | ESP" );
				break;

			case IPSEC_NATT_V01:
				textLabelTransportValue->setText( "NAT-T v01 / IKE | ESP" );
				break;

			case IPSEC_NATT_V02:
				textLabelTransportValue->setText( "NAT-T v02 / IKE | ESP" );
				break;

			case IPSEC_NATT_V03:
				textLabelTransportValue->setText( "NAT-T v03 / IKE | ESP" );
				break;

			case IPSEC_NATT_RFC:
				textLabelTransportValue->setText( "NAT-T RFC / IKE | ESP" );
				break;
		}

		if( event->stats.frag )
			textLabelFragValue->setText( "Enabled" );
		else
			textLabelFragValue->setText( "Disabled" );

		if( event->stats.dpd )
			textLabelDPDValue->setText( "Enabled" );
		else
			textLabelDPDValue->setText( "Disabled" );
	}

	if( e->type() == EVENT_USERNAME )
	{
		UsernameEvent * event = ( UsernameEvent * ) e;
		event->data->text = lineEditUsername->text();
		event->data->result = 0;
	}

	if( e->type() == EVENT_PASSWORD )
	{
		PasswordEvent * event = ( PasswordEvent * ) e;
		event->data->text = lineEditPassword->text();
		event->data->result = 0;

		lineEditPassword->clear();
	}

	if( e->type() == EVENT_FILEPASS )
	{
		FilePassEvent * event = ( FilePassEvent * ) e;

		qikecFilePass fp;
		QFileInfo pathInfo( event->data->filepath );
		fp.setWindowTitle( "Password for " + pathInfo.fileName() );
		event->data->result = fp.exec();
		event->data->password = fp.lineEditPassword->text();
	}
}

void _qikecRoot::siteConnect()
{
	if( qikec.state() != CLIENT_STATE_DISCONNECTED )
	{
		// call ikec disconnect function

		qikec.vpn_disconnect();
	}
	else
	{
		// verify that a valid username and password was supplied

		if( !groupBoxCredentials->isHidden() )
		{
			if( !lineEditUsername->text().length() ||
				!lineEditPassword->text().length() )
			{
				qikec.log( STATUS_FAIL,
					"please enter a valid username and password\n" );
				return;
			}
		}

		// call ikec connect function

		qikec.vpn_connect( false );
	}
}


void _qikecRoot::siteDisconnect()
{
	if( qikec.state() != CLIENT_STATE_DISCONNECTED )
	{
		// call ikec disconnect function

		qikec.vpn_disconnect();
	}
	else
	{
		// close the application

		close();
	}
}
