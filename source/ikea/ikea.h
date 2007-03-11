#ifndef _IKEA_H_
#define _IKEA_H_

#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <qfiledialog.h>
#include <qlineedit.h>
#include <qmessagebox.h>
#include <qprocess.h>
#include "netinet/in.h"
#include "arpa/inet.h"
#include "config.h"
#include "root.h"
#include "site.h"
#include "topology.h"
#include "about.h"

typedef class _IKEA
{
	protected:

	char	sites[ 1024 ];
	char	certs[ 1024 ];

	root *	r;

	public:

	_IKEA();
	~_IKEA();

	char * site_path();
	char * cert_path();

	bool init( root * setr );

}IKEA;

extern IKEA ikea;

#endif
