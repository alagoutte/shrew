#ifndef _IKEA_H_
#define _IKEA_H_

#include <pwd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <qfiledialog.h>
#include <qlabel.h>
#include <qlineedit.h>
#include <qmessagebox.h>
#include <qprocess.h>
#include <qiconview.h>
#include <qdir.h>

#include "../version.h"
#include "config.h"
#include "root.h"
#include "site.h"
#include "topology.h"
#include "about.h"

typedef class _IKEA
{
	protected:

	QString sites;
	QString certs;

	root *	r;

	public:

	_IKEA();
	~_IKEA();

	const char * site_path();
	const char * cert_path();

	bool init( root * setr );

}IKEA;

extern IKEA ikea;

#endif
