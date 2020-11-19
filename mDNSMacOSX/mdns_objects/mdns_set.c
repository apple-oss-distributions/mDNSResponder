/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mdns_set.h"
#include "mdns_helpers.h"
#include "mdns_objects.h"

#include <CoreUtils/CoreUtils.h>

//======================================================================================================================
// MARK: - Set Kind Definition

typedef struct _subset_s * _subset_t;

struct mdns_set_s {
	struct mdns_object_s	base;	// Object base.
	_subset_t				list;	// Subset list.
};

MDNS_OBJECT_SUBKIND_DEFINE(set);

//======================================================================================================================
// MARK: - Internal Data Structures

typedef struct _item_s * _item_t;
struct _item_s {
	_item_t			next;	// Next item in list.
	mdns_object_t	object;	// Object.
};

struct _subset_s {
	_subset_t	next;	// Next subset in list.
	uintptr_t	ident;	// Subset ID.
	_item_t		list;	// Querier list.
	size_t		count;	// Item count.
};

//======================================================================================================================
// MARK: - Internal Helper Function Prototypes

static _subset_t
_subset_create(uintptr_t subset_id);

static void
_subset_free(_subset_t subset);
#define _subset_forget(X) ForgetCustom(X, _subset_free)

static _item_t
_item_create(mdns_object_t object);

static void
_item_free(_item_t item);
#define _item_forget(X) ForgetCustom(X, _item_free)

//======================================================================================================================
// MARK: - Set Public Methods

mdns_set_t
mdns_set_create(void)
{
	return _mdns_set_alloc();
}

//======================================================================================================================

OSStatus
mdns_set_add(const mdns_set_t me, const uintptr_t subset_id, const mdns_object_t object)
{
	_subset_t *subset_ptr;
	_subset_t subset;
	for (subset_ptr = &me->list; (subset = *subset_ptr) != NULL; subset_ptr = &subset->next) {
		if (subset->ident == subset_id) {
			break;
		}
	}
	OSStatus err;
	_subset_t new_subset = NULL;
	if (!subset) {
		new_subset = _subset_create(subset_id);
		require_action_quiet(new_subset, exit, err = kNoMemoryErr);
		subset = new_subset;
	}
	_item_t *item_ptr;
	_item_t item;
	for (item_ptr = &subset->list; (item = *item_ptr) != NULL; item_ptr = &item->next) {
		if (item->object == object) {
			break;
		}
	}
	require_action_quiet(!item, exit, err = kNoErr);

	item = _item_create(object);
	require_action_quiet(item, exit, err = kNoMemoryErr);

	*item_ptr = item;
	item = NULL;
	++subset->count;
	if (new_subset) {
		*subset_ptr = new_subset;
		new_subset = NULL;
	}
	err = kNoErr;

exit:
	_subset_forget(&new_subset);
	return err;
}

//======================================================================================================================

OSStatus
mdns_set_remove(const mdns_set_t me, const uintptr_t subset_id, const mdns_object_t object)
{
	_subset_t *subset_ptr;
	_subset_t subset;
	for (subset_ptr = &me->list; (subset = *subset_ptr) != NULL; subset_ptr = &subset->next) {
		if (subset->ident == subset_id) {
			break;
		}
	}
	OSStatus err;
	require_action_quiet(subset, exit, err = kNotFoundErr);

	_item_t *item_ptr;
	_item_t item;
	for (item_ptr = &subset->list; (item = *item_ptr) != NULL; item_ptr = &item->next) {
		if (item->object == object) {
			break;
		}
	}
	require_action_quiet(item, exit, err = kNotFoundErr);

	*item_ptr = item->next;
	--subset->count;
	_item_forget(&item);
	if (!subset->list) {
		*subset_ptr = subset->next;
		_subset_forget(&subset);
	}
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

size_t
mdns_set_get_count(const mdns_set_t me, const uintptr_t subset_id)
{
	_subset_t subset;
	for (subset = me->list; subset; subset = subset->next) {
		if (subset->ident == subset_id) {
			return subset->count;
		}
	}
	return 0;
}

//======================================================================================================================

void
mdns_set_iterate(const mdns_set_t me, const uintptr_t subset_id, mdns_set_applier_t applier)
{
	_subset_t subset = me->list;
	while (subset && (subset->ident != subset_id)) {
		subset = subset->next;
	}
	require_quiet(subset, exit);

	for (_item_t item = subset->list; item; item = item->next) {
		const bool stop = applier(item->object);
		if (stop) {
			break;
		}
	}

exit:
	return;
}

//======================================================================================================================
// MARK: - Set Private Methods

static char *
_mdns_set_copy_description(const mdns_set_t me, __unused const bool debug, __unused const bool privacy)
{
	char *				description	= NULL;
	char				buffer[128];
	char *				dst			= buffer;
	const char * const	lim			= &buffer[countof(buffer)];
	int					n;

	*dst = '\0';
	n = mdns_snprintf_add(&dst, lim, "<%s: %p>: ", me->base.kind->name, me);
	require_quiet(n >= 0, exit);

	description = strdup(buffer);

exit:
	return description;
}
//======================================================================================================================

static void
_mdns_set_finalize(const mdns_set_t me)
{
	_subset_t subset;
	while ((subset = me->list) != NULL) {
		me->list = subset->next;
		_subset_free(subset);
	}
}

//======================================================================================================================
// MARK: - Internal Helper Functions

static _subset_t
_subset_create(const uintptr_t subset_id)
{
	const _subset_t obj = (_subset_t)calloc(1, sizeof(*obj));
	require_quiet(obj, exit);

	obj->ident = subset_id;

exit:
	return obj;
}

//======================================================================================================================

static void
_subset_free(const _subset_t me)
{
	me->next = NULL;
	_item_t item;
	while ((item = me->list) != NULL) {
		me->list = item->next;
		_item_free(item);
	}
	free(me);
}

//======================================================================================================================

static _item_t
_item_create(mdns_object_t object)
{
	const _item_t obj = (_item_t)calloc(1, sizeof(*obj));
	require_quiet(obj, exit);

	obj->object = object;
	mdns_retain(obj->object);

exit:
	return obj;
}

//======================================================================================================================

static void
_item_free(const _item_t me)
{
	me->next = NULL;
	mdns_forget(&me->object);
	free(me);
}
