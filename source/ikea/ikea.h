#ifndef _IKEA_H_
#define _IKEA_H_

/*

# include <unistd.h>
# include <linux/types.h>
# include <linux/dirent.h>
# include <linux/unistd.h>
# include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
*/

#ifdef __linux__
# include <unistd.h>
# include <linux/types.h>
# include <linux/dirent.h>
# include <linux/unistd.h>
# include <errno.h>
#else
# include <dirent.h>
#endif

#include <pwd.h>
#include <fcntl.h>

#include <qfiledialog.h>
#include <qlineedit.h>
#include <qmessagebox.h>
#include <qprocess.h>

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
