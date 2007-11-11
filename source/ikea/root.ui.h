
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

#include "ikea.h"

static QString selected;

void root::ConnectSite()
{
	QIconViewItem * i = iconViewSites->currentItem();
	if( i != NULL )
	{
		// launch ikec with site name as parameter

		QProcess proc( this );

		proc.addArgument( "ikec" );
		proc.addArgument( "-r" );
		proc.addArgument( i->text().ascii() );

		proc.start();
	}
}

void root::AddSite()
{
	site s( this );
	if( s.exec() == QDialog::Accepted )
	{
		// save site config

		CONFIG config;
		s.Save( config );

		// mangle name if duplicate

		int index = 2;
		QString name = s.lineEditHost->text().ascii();
		while( iconViewSites->findItem( name, Qt::ExactMatch ) != NULL )
			name += " (" + QString::number( index++ ) + ")";

		char path[ 1024 ];
		snprintf( path, 1024, "%s/%s",
			ikea.site_path(),
			name.ascii() );

		config.file_write( path );

		// create icon for site

		QIconViewItem * i = new QIconViewItem( iconViewSites );
		if( i == NULL )
			return;

		i->setPixmap( QPixmap::fromMimeSource( "site.png" ) );
		i->setSelected( true );
		i->setRenameEnabled( true );
		i->setText( name );
		selected = name;
		i->rename();
	}
}

void root::ModSite()
{
	QIconViewItem * i = iconViewSites->currentItem();
	if( i != NULL )
	{
		// load site config

		CONFIG config;

		char path[ 1024 ];
		snprintf( path, 1024, "%s/%s",
			ikea.site_path(),
			i->text().ascii() );

		config.file_read( path );

		// create site modal dialog

		site s( this );
		s.Load( config );

		if( s.exec() == QDialog::Accepted )
		{
			// save the modifications

			s.Save( config );
			config.file_write( path );
		}
	}
}

void root::DelSite()
{
	QIconViewItem * i = iconViewSites->currentItem();
	if( i != NULL )
	{
		QMessageBox m;
		if( m.warning( this,
			   "Warning",
			   "Are you sure you want to delete this site?",
			   QMessageBox::Yes,
			   QMessageBox::Cancel ) != QMessageBox::Yes )
			return;

		char path[ 1024 ];
		snprintf( path, 1024, "%s/%s",
			ikea.site_path(),
			i->text().ascii() );

		unlink( path );
		delete i;
	}
}

void root::ContextSite( QIconViewItem * item, const QPoint & pos )
{
	QPopupMenu m;
	m.insertItem( QPixmap::fromMimeSource( "site_con.png" ), "Connect", 0 );
	m.insertSeparator();
	m.insertItem( QPixmap::fromMimeSource( "site_add.png" ), "Add", 1 );
	m.insertItem( QPixmap::fromMimeSource( "site_del.png" ), "Delete", 2 );
	m.insertItem( "Rename", 3 );
	m.insertSeparator();
	m.insertItem( QPixmap::fromMimeSource( "site_mod.png" ), "Properties", 4 );

	if( item == NULL )
	{
		m.setItemEnabled( 0, false );
		m.setItemEnabled( 2, false );
		m.setItemEnabled( 3, false );
		m.setItemEnabled( 4, false );
	}

	int result = m.exec( pos );
	switch( result )
	{
		case 0:
			ConnectSite();
			break;

		case 1:
			AddSite();
			break;

		case 2:
			DelSite();
			break;

		case 3:
			item->rename();
			break;

		case 4:
			ModSite();
			break;
	}
}

void root::SelectSite( QIconViewItem * item )
{
	//
	// HACK : QIconView item renaming is
	// brain dead. It doesn't offer any
	// kind of validation before modify.
	// We are forced to store the name
	// manulally and revert the value if
	// there is a problem.
	//

	selected = item->text();
}

void root::RenameSite( QIconViewItem * item, const QString & name )
{
	if( selected == name )
		return;

	char path1[ 1024 ];
	snprintf( path1, 1024, "%s/%s",
		ikea.site_path(),
		selected.ascii() );

	char path2[ 1024 ];
	snprintf( path2, 1024, "%s/%s",
		ikea.site_path(),
		name.ascii() );

	struct stat sb;
	if( !stat( path2, &sb ) )
	{
		QMessageBox m;
		if( m.warning( this,
			   "Warning",
			   "A site with the same name already exists. Are your sure you want to overwrite?",
			   QMessageBox::Yes,
			   QMessageBox::Cancel ) != QMessageBox::Yes )
		{
			//
			// aborted
			//

			item->setText( selected );
			return;
		}

		delete item;
	}

	rename( path1, path2 );

	selected = name;
}

void root::About()
{
	about a( this );
	QString Major, Minor, Build;
	Major.setNum( CLIENT_VER_MAJ );
	Minor.setNum( CLIENT_VER_MIN );
	Build.setNum( CLIENT_VER_BLD );
	a.textLabelVersion->setText( "Ver " + Major + "." + Minor + "." + Build );
	a.exec();
}
