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

	ikec.start();
}


void root::SiteDisconnect()
{
	close();
}
