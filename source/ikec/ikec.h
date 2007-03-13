#ifndef _IKEC_H_
#define _IKEC_H_

#include <qapplication.h>
#include <qtextbrowser.h>
#include <qgroupbox.h>
#include <qpushbutton.h>
#include <qlineedit.h>
#include <qlabel.h>
#include <qthread.h>
#include <qevent.h>

#include <pwd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdarg.h>
#include "root.h"
#include "banner.h"
#include "libiked.h"
#include "config.h"

#define EVENT_RUNNING		QEvent::User + 1
#define EVENT_ENABLE		QEvent::User + 2
#define EVENT_STATUS		QEvent::User + 3
#define EVENT_STATS		QEvent::User + 4

class RunningEvent : public QCustomEvent
{
	public:

	bool running;

	RunningEvent( bool value ) : QCustomEvent( EVENT_RUNNING )
	{
		running = value;
	}
};

class EnableEvent : public QCustomEvent
{
	public:

	bool enabled;

	EnableEvent( bool value ) : QCustomEvent( EVENT_ENABLE )
	{
		enabled = value;
	}
};

class StatusEvent : public QCustomEvent
{
	public:

	QString text;
	long	status;

	StatusEvent( QString value, long level ) : QCustomEvent( EVENT_STATUS )
	{
		text = value;
		status = level;
	}
};

class StatsEvent : public QCustomEvent
{
	public:

	IKEI_STATS stats;

	StatsEvent( IKEI_STATS value ) : QCustomEvent( EVENT_STATS )
	{
		stats = value;
	}
};

typedef class _IKEC : public QThread
{
	protected:

	char	fspec[ 255 ];
	char	fpath[ 1024 ];
	char	sites[ 1024 ];

	root *	r;

	IKE_PEER	peer;
	IKE_XCONF       xconf;
	IKE_PROPOSAL    proposal_isakmp;
	IKE_PROPOSAL    proposal_esp;
	IKE_PROPOSAL    proposal_ipcomp;

	void	run();

	public:

	CONFIG	config;
	bool	active;
	bool	cancel;

	QString	username;
	QString	password;

	_IKEC();
	~_IKEC();

	bool	init( root * setr );
	bool	log( long code, char * format, ... );

	char *	file_spec( char * name = NULL );
	char *	file_path();
	char *	site_path();

}IKEC;

extern IKEC ikec;

#endif
