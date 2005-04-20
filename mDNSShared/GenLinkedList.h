/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@

 	File:		GenLinkedList.c

 	Contains:	interface to generic linked lists.

 	Version:	1.0
 	Tabs:		4 spaces

    Change History (most recent first):

$Log: GenLinkedList.h,v $
Revision 1.2  2004/02/05 07:41:08  cheshire
Add Log header

*/

#ifndef __GenLinkedList__
#define __GenLinkedList__


#include <stddef.h>


struct	GenLinkedList
{
	void		*Head,
				*Tail;
	size_t		LinkOffset;
};
typedef struct GenLinkedList	GenLinkedList;


void		InitLinkedList( GenLinkedList *pList, size_t linkOffset);

void		AddToHead( GenLinkedList *pList, void *elem);
void		AddToTail( GenLinkedList *pList, void *elem);

int		RemoveFromList( GenLinkedList *pList, void *elem);

int		ReplaceElem( GenLinkedList *pList, void *elemInList, void *newElem);



struct	GenDoubleLinkedList
{
	void		*Head,
				*Tail;
	size_t		FwdLinkOffset,
				BackLinkOffset;
};
typedef struct GenDoubleLinkedList	GenDoubleLinkedList;


void		InitDoubleLinkedList( GenDoubleLinkedList *pList, size_t fwdLinkOffset,
									  size_t backLinkOffset);

void		DLLAddToHead( GenDoubleLinkedList *pList, void *elem);

void		DLLRemoveFromList( GenDoubleLinkedList *pList, void *elem);



/* A GenLinkedOffsetList is like a GenLinkedList that stores the *Next field as a signed */
/* offset from the address of the beginning of the element, rather than as a pointer. */

struct	GenLinkedOffsetList
{
	size_t		Head,
				Tail;
	size_t		LinkOffset;
};
typedef struct GenLinkedOffsetList	GenLinkedOffsetList;


void		InitLinkedOffsetList( GenLinkedOffsetList *pList, size_t linkOffset);

void		*GetHeadPtr( GenLinkedOffsetList *pList);
void		*GetTailPtr( GenLinkedOffsetList *pList);
void		*GetOffsetLink( GenLinkedOffsetList *pList, void *elem);

void		OffsetAddToHead( GenLinkedOffsetList *pList, void *elem);
void		OffsetAddToTail( GenLinkedOffsetList *pList, void *elem);

int		OffsetRemoveFromList( GenLinkedOffsetList *pList, void *elem);

int		OffsetReplaceElem( GenLinkedOffsetList *pList, void *elemInList, void *newElem);


#endif //	__GenLinkedList__
