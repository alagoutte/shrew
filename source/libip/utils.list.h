
#ifndef	_UTILS_LIST_H_
#define _UTILS_LIST_H_

#include "export.h"
#include <string.h>

#define GROW_SIZE	16

// generic list class
//
// The stack class is a generic
// stack managment class. Mostly,
// this is used as a superclass
// to provide basic funtionality
// for more specific derivations.

typedef class DLX _LIST
{
	void **		item_list;
	long		item_capacity;
	long		item_count;

	bool		grow();

	public:

	_LIST();
	virtual ~_LIST();

	virtual bool	ins_item( void * ins_item, long index );
	virtual bool	add_item( void * add_item );
	virtual bool	del_item( void * del_item );
	virtual void *	get_item( long index );
	virtual long	get_count();

}LIST;

#endif
