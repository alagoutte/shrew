
#include <qapplication.h>
#include "ikea.h"

IKEA ikea;

int main( int argc, char ** argv )
{
	QApplication a( argc, argv );

	// iniitialize our root window

	root r;
	r.show();

	// initialize our ikea config
	// and populate our site list

	ikea.init( &r );
    
	a.connect( &a, SIGNAL( lastWindowClosed() ), &a, SLOT( quit() ) );
    
	return a.exec();
}
