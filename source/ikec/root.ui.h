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

#include "ikec.h"

void root::SiteConnect()
{
	if( ikec.active )
		ikec.cancel = true;
	else
	{
		// if enabled, verify that a valid
		// username and password was supplied

		if( !groupBoxCredentials->isHidden() )
		{
			if( !lineEditUsername->text().length() ||
			    !lineEditPassword->text().length() )
			{
				textBrowserStatus->append( 
					"please enter a valid username and password\n" );
				return;
			}
		}

		// store username and password

		ikec.username = lineEditUsername->text().ascii();
		ikec.password = lineEditPassword->text().ascii();

		// start our thread

		ikec.start();
	}
}


void root::SiteDisconnect()
{
	if( ikec.active )
		ikec.cancel = true;
	else
		close();
}

void root::customEvent( QCustomEvent * e )
{
	if( e->type() == EVENT_RUNNING )
	{
		RunningEvent * event = ( RunningEvent * ) e;

		if( event->running )
		{
			textLabelStatusValue->setText( "Connecting" );

			lineEditUsername->setEnabled( false );
			lineEditPassword->setEnabled( false );

			pushButtonConnect->setEnabled( false );
			pushButtonConnect->setText( "Connect" );

			pushButtonExit->setEnabled( true );
			pushButtonExit->setText( "Cancel" );

			textLabelRemoteValue->setText( event->host );
		}
		else
		{
			textLabelStatusValue->setText( "Disconnected" );

			lineEditUsername->setEnabled( true );
			lineEditPassword->setEnabled( true );

			pushButtonConnect->setEnabled( true );
			pushButtonConnect->setText( "Connect" );

			pushButtonExit->setEnabled( true );
			pushButtonExit->setText( "Exit" );

			textLabelRemoteValue->setText( event->host );
		}
	}

	if( e->type() == EVENT_ENABLE )
	{
		EnableEvent * event = ( EnableEvent * ) e;

		if( event->enabled )
			textBrowserStatus->append( "bringing up tunnel ...\n" );
		else
			textBrowserStatus->append( "bringing down tunnel ...\n" );
	}

	if( e->type() == EVENT_STATUS )
	{
		StatusEvent * event = ( StatusEvent * ) e;

		switch( event->status )
		{
			case STATUS_WARN:

				textBrowserStatus->setColor( QColor( 192, 128, 0 ) );

				break;

			case STATUS_FAIL:

				textBrowserStatus->setColor( QColor( 128, 0, 0 ) );

				break;

			default:

				textBrowserStatus->setColor( QColor( 0, 0, 0 ) );
		}

		switch( event->status )
		{
			case STATUS_BANNER:
			{
				banner b( this );
				b.textBrowserMOTD->setText( event->text );
				b.exec();

				break;
			}

			case STATUS_ENABLED:

				textLabelStatusValue->setText( "Connected" );

				pushButtonConnect->setEnabled( true );
				pushButtonConnect->setText( "Disconnect" );

				pushButtonExit->setEnabled( false );
				pushButtonExit->setText( "Cancel" );

				textBrowserStatus->append( event->text );

				break;

			case STATUS_DISABLED:
			case STATUS_INFO:
			case STATUS_WARN:
			case STATUS_FAIL:

				textBrowserStatus->append( event->text );

				break;

			default:

				textBrowserStatus->append( "!!! unknown status message !!!\n" );
		}
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

		if( event->stats.natt )
			textLabelTransportValue->setText( "NAT-T / IKE | ESP" );
		else
			textLabelTransportValue->setText( "IKE | ESP" );

		if( event->stats.frag )
			textLabelFragValue->setText( "Enabled" );
		else
			textLabelFragValue->setText( "Disabled" );

		if( event->stats.dpd )
			textLabelDPDValue->setText( "Enabled" );
		else
			textLabelDPDValue->setText( "Disabled" );
	}

	if( e->type() == EVENT_FILEPASS )
	{
		FilePassEvent * event = ( FilePassEvent * ) e;

		filepass fp;
		QFileInfo pathInfo( event->PassData->filepath );
		fp.setCaption( "Password for " + pathInfo.fileName());
		event->PassData->result = fp.exec();
		event->PassData->password = fp.lineEditPassword->text();
	}
}
