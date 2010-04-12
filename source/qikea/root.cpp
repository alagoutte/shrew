
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

bool file_to_bdata( QString path, BDATA & bdata )
{
	bdata.del();

	FILE * fp = fopen( path.toAscii(), "rb" );
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

bool bdata_to_file( BDATA & bdata, QString path )
{
	FILE * fp = fopen( path.toAscii(), "wb" );
	if( fp == NULL )
		return false;

	size_t count = bdata.size();
	size_t index = 0;

	for( ; index < count; index++ )
		fputc( bdata.buff()[ index ], fp );

	fclose( fp );

	return true;
}

void filename_mangle( QString & path, QString & name )
{
	// mangle name if duplicate

	int index = 2;

	QString tmpName = name;
	QString tmpPath = path + "/" + name;

	while( QFile::exists( tmpPath ) )
	{
		name  = tmpName;
		name += QString( " (" );
		name += QString::number( index++ );
		name += QString( ")" );

		tmpPath = path + "/" + name;
	}
}

void _ikeaRoot::fileConflict( QString & path, QString & name )
{
	QString tmpName = name;
	QString tmpPath = path + "/" + name;

	while( QFile::exists( tmpPath ) )
	{
		ikeaConflict fc( this );
		fc.lineConflictName->setText( name );

		if( fc.exec() == QDialog::Rejected )
			break;

		name = fc.lineConflictName->text();
		tmpPath = path + "/" + name;
	}
}

void _ikeaRoot::siteContext( const QPoint & pos )
{
	QListWidgetItem * i = listWidgetSites->itemAt( pos );

	menuContextView->clear();
	menuContextView->addAction( actionViewLarge );
	menuContextView->addAction( actionViewSmall );

	menuContext->clear();

	if( i != NULL )
	{
		menuContext->addAction( actionConnect );
		menuContext->addSeparator();
	}

	menuContext->addMenu( menuContextView );
	menuContext->addSeparator();

	menuContext->addSeparator();
	menuContext->addAction( actionAdd );

	if( i != NULL )
	{
		menuContext->addAction( actionDelete );
		menuContext->addAction( actionRename );
		menuContext->addSeparator();
		menuContext->addAction( actionModify );
	}

	//
	// FIXME : If we don't change the position
	// value the popup immediately dissapears
	// when the user right clicks. Why?
	//

	QPoint mpos( listWidgetSites->mapToGlobal( pos ) );
	mpos.setX( mpos.x() + 1 );

	menuContext->popup( mpos );
}

void _ikeaRoot::showViewLarge()
{
	listWidgetSites->setViewMode( QListView::IconMode );
}

void _ikeaRoot::showViewSmall()
{
	listWidgetSites->setViewMode( QListView::ListMode );
}

void _ikeaRoot::siteConnect()
{
	QListWidgetItem * i = listWidgetSites->currentItem();
	if( i == NULL )
		return;

	// launch ikec with site name as parameter

	QStringList args;
	args << "-r";
	args << i->text();

	QProcess * proc = new QProcess( this );
	proc->start( "ikec-qt", args );
}

void _ikeaRoot::siteAdd()
{
	ikeaSite s( this );
	if( s.exec() != QDialog::Accepted )
		return;

	// save site config

	CONFIG config;
	config.set_number( "version", CLIENT_VER_CFG );
	s.save( config );

	QString siteName = s.lineEditHost->text();

	// mangle name if duplicate

	filename_mangle( ikea.sites, siteName );

	// write site config

	QString sitePath = ikea.sites + "/" + siteName;
	config.file_write( sitePath.toAscii() );

	// create icon for site

	QListWidgetItem * i = new QListWidgetItem( listWidgetSites );
	if( i == NULL )
		return;

	i->setIcon( QIcon( ":/png/site.png" ) );
	i->setText( siteName );
	i->setData( Qt::UserRole, siteName );
	i->setFlags( Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsEditable );
	i->setSelected( true );
	listWidgetSites->editItem( i );
}

void _ikeaRoot::siteModify()
{
	QListWidgetItem * i = listWidgetSites->currentItem();
	if( i == NULL )
		return;

	// load site config

	QString filePath = ikea.sites + "/" + i->text();

	CONFIG config;
	config.file_read( filePath.toAscii() );

	// create site modal dialog

	ikeaSite s( this );
	s.load( config );

	if( s.exec() == QDialog::Accepted )
	{
		// save modified site config

		s.save( config );
		config.file_write( filePath.toAscii() );
	}
}

void _ikeaRoot::siteDelete()
{
	QListWidgetItem * i = listWidgetSites->currentItem();
	if( i == NULL )
		return;

	QMessageBox m;
	if( m.question( this,
		"Confirm Delete",
		"Are you sure you want to delete this site?",
		QMessageBox::Yes, QMessageBox::Cancel ) != QMessageBox::Yes )
		return;

	QString filePath = ikea.sites + "/" + i->text();

	unlink( filePath.toAscii() );
	delete i;
}

void _ikeaRoot::siteRename()
{
	QListWidgetItem * i = listWidgetSites->currentItem();
	if( i == NULL )
		return;

	listWidgetSites->editItem( i );
}

void _ikeaRoot::siteRenamed( QListWidgetItem * i )
{
	QString oldName = i->data( Qt::UserRole ).toString();
	QString modName = i->text();

	if( !oldName.length() || ( oldName == modName ) )
		return;

	if( !modName.length() )
	{
		i->setText( oldName );
		return;
	}

	filename_mangle( ikea.sites, modName );

	QString oldPath = ikea.sites + "/" + oldName;
	QString modPath = ikea.sites + "/" + modName;

	printf( "name = %s\n", ( const char * ) modName.toAscii() );
	printf( "path = %s\n", ( const char * ) modPath.toAscii() );

	QFile::rename( oldPath, modPath );
	i->setText( modName );
	i->setData( Qt::UserRole, modName );
}

void _ikeaRoot::siteImport()
{
	// get the input path

	QString types(
		"Shrew Soft VPN file (*.vpn);;"
		"Cisco PCF file (*.pcf);;"
		"All files (*)" );

	QString loadPath = QFileDialog::getOpenFileName(
				this, "Select the Import File",
				QDir::homePath(),
				types );

	if( !loadPath.length() )
		return;

	// load the site config

	CONFIG config;

	bool need_certs = false;

	if( !loadPath.contains( ".pcf", Qt::CaseInsensitive ) )
		config.file_read( loadPath.toAscii() );
	else
		config.file_import_pcf( loadPath.toAscii(), need_certs );

	// modify for import

	char	name[ 1024 ];
	BDATA	data;

	if( config.get_binary( "auth-client-cert-data", data ) &&
	    config.get_string( "auth-client-cert", name, 1023, 0 ) )
	{
		QString tmpName = name;

		fileConflict( ikea.certs, tmpName );

		QString tmpPath = ikea.certs + "/" + tmpName;

		bdata_to_file( data, tmpPath );

		config.set_string( "auth-client-cert", tmpPath.toAscii(), tmpPath.length() );
		config.del( "auth-client-cert-data" );
	}

	if( config.get_binary( "auth-client-key-data", data ) &&
	    config.get_string( "auth-client-key", name, 1023, 0 ) )
	{
		QString tmpName = name;

		fileConflict( ikea.certs, tmpName );

		QString tmpPath = ikea.certs + "/" + tmpName;

		bdata_to_file( data, tmpPath );

		config.set_string( "auth-client-key", tmpPath.toAscii(), tmpPath.length() );
		config.del( "auth-client-key-data" );
	}

	if( config.get_binary( "auth-server-cert-data", data ) &&
	    config.get_string( "auth-server-cert", name, 1023, 0 ) )
	{
		QString tmpName = name;

		fileConflict( ikea.certs, tmpName );

		QString tmpPath = ikea.certs + "/" + tmpName;

		bdata_to_file( data, tmpPath );

		config.set_string( "auth-server-cert", tmpPath.toAscii(), tmpPath.length() );
		config.del( "auth-server-cert-data" );
	}

	// determine file name

	QFileInfo fileInfo( loadPath );
	QString fileName = fileInfo.baseName();

	// mangle name if duplicate

	filename_mangle( ikea.sites, fileName );

	// save the site config

	QString filePath = ikea.sites + "/" + fileName;
	config.file_write( filePath.toAscii() );

	// update the site version if required

	long version = 0;
	config.get_number( "version", &version );
	while( version < CLIENT_VER_CFG )
		update_site( &config, filePath.toAscii(), version );

	// create icon for site

	QListWidgetItem * i = new QListWidgetItem( listWidgetSites );
	if( i == NULL )
		return;

	i->setIcon( QIcon( ":/png/site.png" ) );
	i->setText( fileName );
	i->setData( Qt::UserRole, fileName );
	i->setFlags( Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsEditable );
	i->setSelected( true );

	if( need_certs )
	{
		QMessageBox m;

		m.warning( this,
			"Site Import Warning",
			"The Cisco site configuration was imported but uses "
			"an RSA authentication method. You will need to import "
			"a certificate manually to complete the configuration.",
			QMessageBox::Ok,
			QMessageBox::NoButton,
			QMessageBox::NoButton );
	}

	listWidgetSites->editItem( i );
}

void _ikeaRoot::siteExport()
{
	QListWidgetItem * i = listWidgetSites->currentItem();
	if( i == NULL )
		return;

	// load site config

	QString filePath = ikea.sites + "/" + i->text();

	CONFIG config;
	config.file_read( filePath.toAscii() );

	// get the output path

	QString types(
				"Site Configurations files (*.vpn);;"
				"All files (*)" );

	QString savePath = QFileDialog::getSaveFileName(
				this, "Select the VPN Export File",
				QDir::homePath() + "/" + i->text() + ".vpn",
				types );

	if( !savePath.length() )
		return;

	// modify for export

	char	path[ 1024 ];
	BDATA	data;

	if( config.get_string( "auth-client-cert", path, 1023, 0 ) )
	{
		QString tmpPath = path;

		file_to_bdata( tmpPath, data );

		QFileInfo fileInfo( tmpPath );
		QString fileName = fileInfo.fileName();

		config.set_string( "auth-client-cert", fileName.toAscii(), fileName.length() );
		config.set_binary( "auth-client-cert-data", data );
	}

	if( config.get_string( "auth-client-key", path, 1023, 0 ) )
	{
		QString tmpPath = path;

		file_to_bdata( tmpPath, data );

		QFileInfo fileInfo( tmpPath );
		QString fileName = fileInfo.fileName();

		config.set_string( "auth-client-key", fileName.toAscii(), fileName.length() );
		config.set_binary( "auth-client-key-data", data );
	}

	if( config.get_string( "auth-server-cert", path, 1023, 0 ) )
	{
		QString tmpPath = path;

		file_to_bdata( tmpPath, data );

		QFileInfo fileInfo( tmpPath );
		QString fileName = fileInfo.fileName();

		config.set_string( "auth-server-cert", fileName.toAscii(), fileName.length() );
		config.set_binary( "auth-server-cert-data", data );
	}

	config.file_write( savePath.toAscii() );
}

void _ikeaRoot::showAbout()
{
	ikeaAbout a( this );
	QString Major, Minor, Build;
	Major.setNum( CLIENT_VER_MAJ );
	Minor.setNum( CLIENT_VER_MIN );
	Build.setNum( CLIENT_VER_BLD );
	a.textLabelVersion->setText( "Ver " + Major + "." + Minor + "." + Build );
	a.exec();
}

