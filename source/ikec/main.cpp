#include "ikec.h"

IKEC ikec;

int main( int argc, char ** argv )
{
	signal( SIGPIPE, SIG_IGN );

	// init the app

	QApplication a( argc, argv );

	// create our root window

	root w;

	// init our ikec object

	ikec.init( &w );

	// read our command line args

	bool syntax_error = true;

	for( int argi = 0; argi < argc; argi++ )
	{
		// remote site name

		if( !strcmp( argv[ argi ], "-r" ) )
		{
			if( ++argi >= argc )
				break;

			ikec.file_spec( argv[ argi++ ] );
			syntax_error = false;
		}
	}

	if( syntax_error )
	{
		ikec.log( STATUS_FAIL,
			"invalid parameters specified ...\n" );

		ikec.log( STATUS_INFO,
			"ikec -r \"name\" [ -u <user> ][ -p <pass> ][ -a ]\n"
			"  -r\tsite configuration path\n"
			"  -u\tconnection user name\n"
			"  -p\tconnection user password\n"
			"  -a\tauto connect\n" );

		w.pushButtonConnect->setHidden( true );
		w.groupBoxCredentials->setHidden( true );
	}
	else
	{
		// load site config

		if( ikec.config.file_read( ikec.file_path() ) )
		{
			// config loaded

			ikec.log( STATUS_INFO, "config loaded for site \'%s\'\n",
				ikec.file_spec() );
		}
		else
		{
			// config load failed

			ikec.log( STATUS_INFO, "failed to load \'%s\'\n",
				ikec.file_spec() );

			w.pushButtonConnect->setHidden( true );
			w.groupBoxCredentials->setHidden( true );
		}

		// hide the credentials group
		// if the autentication method
		// does not require xauth

		char auth_method[ 64 ] = { 0 };
		ikec.config.get_string( "auth-method",
		auth_method, 63, 0 );

		if( strstr( auth_method, "xauth" ) == NULL )
			w.groupBoxCredentials->setHidden( true );
	}

	// show the root window

	w.show();

	a.connect( &a, SIGNAL( lastWindowClosed() ), &a, SLOT( quit() ) );

	return a.exec();
}
