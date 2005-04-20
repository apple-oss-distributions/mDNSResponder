/*
 * Copyright (c) 1997-2004 Apple Computer, Inc. All rights reserved.
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

    Change History (most recent first):
    
$Log: UtilTypes.h,v $
Revision 1.11  2005/03/05 02:27:46  shersche
<rdar://problem/4030388> Generic drivers don't do color

Revision 1.10  2005/02/08 21:45:06  shersche
<rdar://problem/3947490> Default to Generic PostScript or PCL if unable to match driver

Revision 1.9  2005/02/01 01:16:12  shersche
Change window owner from CSecondPage to CPrinterSetupWizardSheet

Revision 1.8  2005/01/06 08:18:26  shersche
Add protocol field to service, add EmptyQueues() function to service

Revision 1.7  2005/01/04 21:07:29  shersche
add description member to service object.  this member corresponds to the 'ty' key in a printer text record

Revision 1.6  2004/12/30 01:24:02  shersche
<rdar://problem/3906182> Remove references to description key
Bug #: 3906182

Revision 1.5  2004/12/29 18:53:38  shersche
<rdar://problem/3725106>
<rdar://problem/3737413> Added support for LPR and IPP protocols as well as support for obtaining multiple text records. Reorganized and simplified codebase.
Bug #: 3725106, 3737413

Revision 1.4  2004/09/13 21:22:44  shersche
<rdar://problem/3796483> Add moreComing argument to OnAddPrinter and OnRemovePrinter callbacks
Bug #: 3796483

Revision 1.3  2004/06/26 23:27:12  shersche
support for installing multiple printers of the same name

Revision 1.2  2004/06/25 02:25:59  shersche
Remove item field from manufacturer and model structures
Submitted by: herscher

Revision 1.1  2004/06/18 04:36:58  rpantos
First checked in


*/

#pragma once

#include <dns_sd.h>
#include <string>
#include <list>
#include <DebugServices.h>

class CPrinterSetupWizardSheet;

#define	kDefaultPriority	50
#define kDefaultQTotal		1

namespace PrinterSetupWizard
{
	struct Printer;
	struct Service;
	struct Queue;
	struct Manufacturer;
	struct Model;

	typedef std::list<Queue*>	Queues;
	typedef std::list<Printer*>	Printers;
	typedef std::list<Service*>	Services;
	typedef std::list<Model*>	Models;

	struct Printer
	{
		Printer();

		~Printer();

		Service*
		LookupService
			(
			const std::string	&	type
			);

		CPrinterSetupWizardSheet	*	window;
		HTREEITEM		item;

		//
		// These are from the browse reply
		//
		std::string		name;
		CString			displayName;
		CString			actualName;

		//
		// These keep track of the different services associated with this printer.
		// the services are ordered according to preference.
		//
		Services		services;

		//
		// these are derived from the printer matching code
		//
		// if driverInstalled is false, then infFileName should
		// have an absolute path to the printers inf file.  this
		// is used to install the printer from printui.dll
		//
		// if driverInstalled is true, then model is the name
		// of the driver to use in AddPrinter
		// 
		bool			driverInstalled;
		CString			infFileName;
		CString			manufacturer;
		CString			displayModelName;
		CString			modelName;
		CString			portName;
		bool			deflt;

		//
		// state
		//
		unsigned		resolving;
		bool			installed;
	};


	struct Service
	{
		Service();

		~Service();

		void
		EmptyQueues();

		Printer		*	printer;
		uint32_t		ifi;
		std::string		type;
		std::string		domain;

		//
		// these are from the resolve
		//
		DNSServiceRef	serviceRef;
		CString			hostname;
		unsigned short	portNumber;
		CString			pdl;
		CString			usb_MFG;
		CString			usb_MDL;
		CString			description;
		CString			location;
		CString			product;
		CString			protocol;
		unsigned short	qtotal;

		//
		// There will usually one be one of these, however
		// this will handle printers that have multiple
		// queues.  These are ordered according to preference.
		//
		Queues			queues;

		//
		// Reference count
		//
		unsigned		refs;
	};


	struct Queue
	{
		Queue();

		~Queue();

		CString		name;
		uint32_t	priority;
	};


	struct Manufacturer
	{
		CString		name;
		CString		tag;
		Models		models;

		Model*
		find( const CString & name );
	};


	struct Model
	{
		bool		driverInstalled;
		CString		infFileName;
		CString		displayName;
		CString		name;
	};


	inline
	Printer::Printer()
	{
	}

	inline
	Printer::~Printer()
	{
		while ( services.size() > 0 )
		{
			Service * service = services.front();
			services.pop_front();
			delete service;
		}
	}

	inline Service*
	Printer::LookupService
				(
				const std::string	&	type
				)
	{
		Services::iterator it;

		for ( it = services.begin(); it != services.end(); it++ )
		{
			Service * service = *it;

			if ( strcmp(service->type.c_str(), type.c_str()) == 0 )
			{
				return service;
			}
		}

		return NULL;
	}

	inline
	Service::Service()
	:
		qtotal(kDefaultQTotal)
	{
	}

	inline
	Service::~Service()
	{
		check( serviceRef == NULL );

		EmptyQueues();
	}

	inline void
	Service::EmptyQueues()
	{
		while ( queues.size() > 0 )
		{
			Queue * q = queues.front();
			queues.pop_front();
			delete q;
		}
	}

	inline
	Queue::Queue()
	:
		priority(kDefaultPriority)
	{
	}

	inline
	Queue::~Queue()
	{
	}

	inline Model*
	Manufacturer::find( const CString & name )
	{
		Models::iterator it;

		for ( it = models.begin(); it != models.end(); it++ )
		{
			Model * model = *it;

			if ( model->name = name )
			{
				return model;
			}
		}

		return NULL;
	}
}


