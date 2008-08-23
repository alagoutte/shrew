
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

bool file_exists( const char * path )
{
	struct stat sb;
	return( stat( path, &sb ) == 0 );
}

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
		config.set_number( "version", CLIENT_VER_CFG );
		s.Save( config );

		// mangle name if duplicate

		int index = 2;
		QString tmpname = s.lineEditHost->text().ascii();
		while( iconViewSites->findItem( tmpname, Qt::ExactMatch ) != NULL )
		{
			tmpname = s.lineEditHost->text().ascii();
			tmpname += QString( " (" );
			tmpname += QString::number( index++ );
			tmpname += QString( ")" );
		}

		char path[ 1024 ];
		snprintf( path, 1024, "%s/%s",
			ikea.site_path(),
			tmpname.ascii() );

		config.file_write( path );

		// create icon for site

		QIconViewItem * i = new QIconViewItem( iconViewSites );
		if( i == NULL )
			return;

		i->setPixmap( QPixmap::fromMimeSource( "site.png" ) );
		i->setSelected( true );
		i->setRenameEnabled( true );
		i->setText( tmpname );
		selected = tmpname;
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

	// mangle name if duplicate

	int index = 2;
	QString tmpname = name;

	while( file_exists( path2 ) )
	{
		tmpname = name;
		tmpname += QString( " (" );
		tmpname += QString::number( index++ );
		tmpname += QString( ")" );

		snprintf( path2, 1024, "%s/%s",
			ikea.site_path(),
			tmpname.ascii() );
	}

	printf( "name = %s\n", tmpname.ascii() );
	printf( "path = %s\n", path2 );

	rename( path1, path2 );
	item->setText( tmpname );

	selected = tmpname;
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

bool file_to_bdata( char * path, BDATA & bdata )
{
	bdata.del();

	FILE * fp = fopen( path, "rb" );
	if( fp == NULL )
		return false;

	while( true )
	{
		int next = fgetc( fp );
		if( next == EOF )
			break;

		bdata.add( next, 1 );
	}

	fclose( fp );

	return ( bdata.size() > 0 );
}

bool bdata_to_file( BDATA & bdata, char * path )
{
	FILE * fp = fopen( path, "wb" );
	if( fp == NULL )
		return false;

	size_t count = bdata.size();
	size_t index = 0;

	for( ; index < count; index++ )
		fputc( bdata.buff()[ index ], fp );

	fclose( fp );

	return true;
}

void root::ImportSite()
{
	// get the input path

        QString types(
                "OpenSSL Files (*.vpn);;"
                "All files (*)" );

        QFileDialog f( this );
        f.setFilters( types );

        if( f.exec() != QDialog::Accepted )
		return;

	// load the site config

	CONFIG config;
	config.file_read( f.selectedFile().ascii() );

	// modify for import

	char tmpfile[ 1024 ];
	char tmppath[ 1024 ];
	BDATA tmpdata;

	if( config.get_binary( "auth-client-cert-data", tmpdata ) &&
	    config.get_string( "auth-client-cert", tmpfile, 1023, 0 ) )
	{
		snprintf( tmppath, 1023, "%s/%s", ikea.cert_path(), tmpfile );

		while( file_exists( tmppath ) )
		{
			conflict fc( this );
			fc.lineConflictName->setText( tmpfile );

			if( fc.exec() == CONFLICT_OVERWRITE )
				break;

			snprintf( tmppath, 1023, "%s/%s", ikea.cert_path(),
				fc.lineConflictName->text().ascii() );
		}

		bdata_to_file( tmpdata, tmppath );

		config.set_string( "auth-client-cert", tmppath, strlen( tmppath ) );
		config.del( "auth-client-cert-data" );
	}

	if( config.get_binary( "auth-client-key-data", tmpdata ) &&
	    config.get_string( "auth-client-key", tmpfile, 1023, 0 ) )
	{
		snprintf( tmppath, 1023, "%s/%s", ikea.cert_path(), tmpfile );

		while( file_exists( tmppath ) )
		{
			conflict fc( this );
			fc.lineConflictName->setText( tmpfile );

			if( fc.exec() == CONFLICT_OVERWRITE )
				break;

			snprintf( tmppath, 1023, "%s/%s", ikea.cert_path(),
				fc.lineConflictName->text().ascii() );
		}

		bdata_to_file( tmpdata, tmppath );

		config.set_string( "auth-client-key", tmppath, strlen( tmppath ) );
		config.del( "auth-client-key-data" );
	}

	if( config.get_binary( "auth-server-cert-data", tmpdata ) &&
	    config.get_string( "auth-server-cert", tmpfile, 1023, 0 ) )
	{
		snprintf( tmppath, 1023, "%s/%s", ikea.cert_path(), tmpfile );

		while( file_exists( tmppath ) )
		{
			conflict fc( this );
			fc.lineConflictName->setText( tmpfile );

			if( fc.exec() == CONFLICT_OVERWRITE )
				break;

			snprintf( tmppath, 1023, "%s/%s", ikea.cert_path(),
				fc.lineConflictName->text().ascii() );
		}

		bdata_to_file( tmpdata, tmppath );

		config.set_string( "auth-server-cert", tmppath, strlen( tmppath ) );
		config.del( "auth-server-cert-data" );
	}

	// determine filespec name

	long oset = 0;
	if( f.selectedFile().find( '/' ) != -1 )
		oset = f.selectedFile().findRev( '/' ) + 1;

	QString filespec = f.selectedFile().ascii() + oset;

	// mangle name if duplicate

	int index = 2;
	QString tmpname = filespec;

	while( iconViewSites->findItem( tmpname, Qt::ExactMatch ) != NULL )
	{
		tmpname = filespec;
		tmpname += QString( " (" );
		tmpname += QString::number( index++ );
		tmpname += QString( ")" );
	}

	// save the site config

	snprintf( tmppath, 1024, "%s/%s", ikea.site_path(), tmpname.ascii() );

	config.file_write( tmppath );

	// update the site version if required

	long version = 0;
	config.get_number( "version", &version );
	while( version < CLIENT_VER_CFG )
		update_site( &config, tmppath, version );

	// create icon for site

	QIconViewItem * i = new QIconViewItem( iconViewSites );
	if( i == NULL )
		return;

	i->setPixmap( QPixmap::fromMimeSource( "site.png" ) );
	i->setSelected( true );
	i->setRenameEnabled( true );
	i->setText( tmpname );
	selected = tmpname;
	i->rename();
}

void root::ExportSite()
{
	QIconViewItem * i = iconViewSites->currentItem();
	if( i == NULL )
		return;

	// load site config

	CONFIG config;

	char path[ 1024 ];
	snprintf( path, 1024, "%s/%s",
		ikea.site_path(),
		i->text().ascii() );

	config.file_read( path );

	// get the output path

        QString types(
                "OpenSSL Files (*.vpn);;"
                "All files (*)" );

        QFileDialog f( this );
	f.setMode( QFileDialog::AnyFile );
        f.setDir( ikea.site_path() );
        f.setFilters( types );

        if( f.exec() != QDialog::Accepted )
		return;

	// modify for export

	char tmppath[ 1024 ];
	BDATA tmpdata;

	if( config.get_string( "auth-client-cert", tmppath, 1023, 0 ) )
	{
		file_to_bdata( tmppath, tmpdata );

		char * tmpfile = tmppath;
		if( strchr( tmpfile, '/' ) )
			tmpfile = strrchr( tmpfile, '/' );

		config.set_string( "auth-client-cert", tmpfile, strlen( tmpfile ) );
		config.set_binary( "auth-client-cert-data", tmpdata );
	}

	if( config.get_string( "auth-client-key", tmppath, 1023, 0 ) )
	{
		file_to_bdata( tmppath, tmpdata );

		char * tmpfile = tmppath;
		if( strchr( tmpfile, '/' ) )
			tmpfile = strrchr( tmpfile, '/' );

		config.set_string( "auth-client-key", tmpfile, strlen( tmpfile ) );
		config.set_binary( "auth-client-key-data", tmpdata );
	}

	if( config.get_string( "auth-server-cert", tmppath, 1023, 0 ) )
	{
		file_to_bdata( tmppath, tmpdata );

		char * tmpfile = tmppath;
		if( strchr( tmpfile, '/' ) )
			tmpfile = strrchr( tmpfile, '/' );

		config.set_string( "auth-server-cert", tmpfile, strlen( tmpfile ) );
		config.set_binary( "auth-server-cert-data", tmpdata );
	}

	config.file_write( f.selectedFile().ascii() );
}
