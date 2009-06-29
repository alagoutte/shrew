
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

#ifndef _IKEC_H_
#define _IKEC_H_

#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <stdarg.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <QEvent>
#include <QThread>
#include <QFileInfo>

#include "libike.h"
#include "../ikec/config.h"
#include "ui_root.h"
#include "ui_banner.h"
#include "ui_filepass.h"

#define EVENT_RUNNING		QEvent::Type( QEvent::User + 1 )
#define EVENT_ENABLE		QEvent::Type( QEvent::User + 2 )
#define EVENT_STATUS		QEvent::Type( QEvent::User + 3 )
#define EVENT_STATS		QEvent::Type( QEvent::User + 4 )
#define EVENT_FILEPASS		QEvent::Type( QEvent::User + 5 )

class RunningEvent : public QEvent
{
	public:

	bool running;

	RunningEvent( bool value ) : QEvent( EVENT_RUNNING )
	{
		running = value;
	}
};

class EnableEvent : public QEvent
{
	public:

	bool enabled;

	EnableEvent( bool value ) : QEvent( EVENT_ENABLE )
	{
		enabled = value;
	}
};

class StatusEvent : public QEvent
{
	public:

	QString text;
	long	status;

	StatusEvent( QString value, long level ) : QEvent( EVENT_STATUS )
	{
		text = value;
		status = level;
	}
};

class StatsEvent : public QEvent
{
	public:

	IKEI_STATS stats;

	StatsEvent( IKEI_STATS value ) : QEvent( EVENT_STATS )
	{
		stats = value;
	}
};

class FilePassData
{
	public:

	QString	filepath;
	QString	password;
	int	result;

	FilePassData()
	{
		result = -1;
	}
};

class FilePassEvent : public QEvent
{
	public:

	FilePassData *	PassData;

	FilePassEvent( FilePassData * CallData ) : QEvent( EVENT_FILEPASS )
	{
		PassData = CallData;
	}
};

typedef class _ikecRoot : public QMainWindow, public Ui::ikecRoot
{
	Q_OBJECT

	public:

	_ikecRoot( QWidget * parent = NULL ) : QMainWindow( parent )
	{
		setupUi( this );

		connect( pushButtonConnect, SIGNAL( clicked() ), this, SLOT( siteConnect() ) );
		connect( pushButtonExit, SIGNAL( clicked() ), this, SLOT( siteDisconnect() ) );

		lineEditUsername->setFocus();
	}

	public slots:

	void customEvent( QEvent * e );

	void siteConnect();
	void siteDisconnect();

}ikecRoot;

typedef class _ikecBanner : public QDialog, public Ui::ikecBanner
{
	Q_OBJECT

	public:

	_ikecBanner( QWidget * parent = NULL ) : QDialog( parent )
	{
		setupUi( this );

		connect( buttonOk, SIGNAL( clicked() ), this, SLOT( accept() ) );
	}

}ikecBanner;

typedef class _ikecFilePass : public QDialog, public Ui::ikecFilePass
{
	Q_OBJECT

	public:

	_ikecFilePass( QWidget * parent = NULL ) : QDialog( parent )
	{
		setupUi( this );

		connect( buttonOk, SIGNAL( clicked() ), this, SLOT( accept() ) );
		connect( buttonCancel, SIGNAL( clicked() ), this, SLOT( reject() ) );
	}

}ikecFilePass;

typedef class _IKEC : public QThread
{
	friend class _ikecRoot;
	
	protected:

	char	fspec[ 255 ];
	char	fpath[ 1024 ];
	char	sites[ 1024 ];

	ikecRoot * r;

	IKE_PEER	peer;
	IKE_XCONF       xconf;
	IKE_PROPOSAL    proposal_isakmp;
	IKE_PROPOSAL    proposal_esp;
	IKE_PROPOSAL    proposal_ipcomp;
	IKEI		ikei;

	void	run();

	public:

	CONFIG	config;
	bool	active;

	QString	username;
	QString	password;

	_IKEC();
	~_IKEC();

	bool	init( ikecRoot * setr );
	bool	log( long code, const char * format, ... );

	char *	file_spec( char * name = NULL );
	char *	file_path();
	char *	site_path();

}IKEC;

extern IKEC ikec;

#endif
