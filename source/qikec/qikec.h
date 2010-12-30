
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

#ifndef _QIKEC_H_
#define _QIKEC_H_

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

#include "client.h"
#include "config.h"
#include "ui_root.h"
#include "ui_banner.h"
#include "ui_filepass.h"

#define EVENT_STATUS		QEvent::Type( QEvent::User + 1 )
#define EVENT_STATE			QEvent::Type( QEvent::User + 2 )
#define EVENT_STATS			QEvent::Type( QEvent::User + 3 )
#define EVENT_USERNAME		QEvent::Type( QEvent::User + 4 )
#define EVENT_PASSWORD		QEvent::Type( QEvent::User + 5 )
#define EVENT_FILEPASS		QEvent::Type( QEvent::User + 6 )

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

class TextData
{
	public:

	QString	text;
	int		result;

	TextData()
	{
		result = -1;
	}
};

class UsernameEvent : public QEvent
{
	public:

	TextData * data;
	
	UsernameEvent( TextData * value ) : QEvent( EVENT_USERNAME )
	{
		data = value;
	}
};

class PasswordEvent : public QEvent
{
	public:

	TextData * data;
	
	PasswordEvent( TextData * value ) : QEvent( EVENT_PASSWORD )
	{
		data = value;
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

	FilePassData * data;

	FilePassEvent( FilePassData * value ) : QEvent( EVENT_FILEPASS )
	{
		data = value;
	}
};

typedef class _qikecRoot : public QMainWindow, public Ui::ikecRoot
{
	Q_OBJECT

	public:

	_qikecRoot( QWidget * parent = NULL ) : QMainWindow( parent )
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

}qikecRoot;

typedef class _qikecBanner : public QDialog, public Ui::ikecBanner
{
	Q_OBJECT

	public:

	_qikecBanner( QWidget * parent = NULL ) : QDialog( parent )
	{
		setupUi( this );

		connect( buttonOk, SIGNAL( clicked() ), this, SLOT( accept() ) );
	}

}qikecBanner;

typedef class _qikecFilePass : public QDialog, public Ui::ikecFilePass
{
	Q_OBJECT

	public:

	_qikecFilePass( QWidget * parent = NULL ) : QDialog( parent )
	{
		setupUi( this );

		connect( buttonOk, SIGNAL( clicked() ), this, SLOT( accept() ) );
		connect( buttonCancel, SIGNAL( clicked() ), this, SLOT( reject() ) );
	}

}qikecFilePass;

typedef class _QIKEC : public _CLIENT, public QThread
{
	friend class _qikecRoot;
	
	protected:

	qikecRoot * r;

	public:

	const char * app_name();

	bool get_username();
	bool get_password();
	bool get_filepass( BDATA & path );

	bool set_stats();
	bool set_status( long status, BDATA * text );

	bool init( int argc, char ** argv, qikecRoot * setr );
	bool log( long code, const char * format, ... );

}QIKEC;

extern QIKEC qikec;

#endif
