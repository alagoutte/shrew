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
				ikec.log( 0, "please enter a valid username and password\n" );
				return;
			}
		}

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
	if( e->type() == EVENT_CONNECTING )
	{
		textLabelStatusValue->setText( "Connecting" );

		lineEditUsername->setEnabled( false );
		lineEditPassword->setEnabled( false );

		pushButtonConnect->setEnabled( false );
		pushButtonExit->setEnabled( true );
                                                
		pushButtonConnect->setText( "Connect" );
		pushButtonExit->setText( "Cancel" );
	}

	if( e->type() == EVENT_CONNECTED )
	{
		textLabelStatusValue->setText( "Connected" );

		pushButtonConnect->setEnabled( true );
		pushButtonExit->setEnabled( false );
                                                
		pushButtonConnect->setText( "Disconnect" );
		pushButtonExit->setText( "Cancel" );
	}

	if( e->type() == EVENT_DISCONNECTED )
	{
		textLabelStatusValue->setText( "Disabled" );

		lineEditUsername->setEnabled( true );
		lineEditPassword->setEnabled( true );

		pushButtonConnect->setEnabled( true );
		pushButtonExit->setEnabled( true );
                                                
		pushButtonConnect->setText( "Connect" );
		pushButtonExit->setText( "Exit" );
	}

	if( e->type() == EVENT_BANNER )
	{
		banner b( this );
		b.textBrowserMOTD->setText( ikec.banner );
		b.exec();
	}
}
