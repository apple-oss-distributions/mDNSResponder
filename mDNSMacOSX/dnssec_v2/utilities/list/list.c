//
//  list.c
//  mDNSResponder
//
//  Copyright (c) 2020 Apple Inc. All rights reserved.
//

#pragma mark - Includes
#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "list.h"

#pragma mark - list_init
mDNSexport void
list_init(list_t * const _Nonnull list_to_init, const mDNSu32 new_data_size) {
	// use dummy head and tail to handle the corner case such as adding node to empty list
	list_to_init->head_ptr			= &(list_to_init->head);
	list_to_init->tail_ptr			= &(list_to_init->tail);
	list_to_init->head_ptr->next	= list_to_init->tail_ptr;
	list_to_init->tail_ptr->prev	= list_to_init->head_ptr;
	// data size is used to prevent from adding different structures into list
	list_to_init->data_size			= new_data_size;
}

#pragma mark - list_append_uinitialized
mDNSexport mStatus
list_append_uinitialized(list_t * const _Nonnull list_ptr, const mDNSu32 new_data_size, void * _Nullable * _Nonnull out_data_ptr) {
	mStatus			error		= mStatus_NoError;
	list_node_t *	node_ptr	= mDNSNULL;
	list_node_t *	real_tail	= mDNSNULL;

	require_action(list_ptr->data_size == new_data_size, exit, error = mStatus_BadParamErr);

	node_ptr = malloc(offsetof(list_node_t, data) + new_data_size);
	require_action(node_ptr != mDNSNULL, exit, error = mStatus_NoMemoryErr);

	*out_data_ptr = &node_ptr->data;

	real_tail					= list_ptr->tail_ptr->prev;
	real_tail->next				= node_ptr;
	node_ptr->prev				= real_tail;
	node_ptr->next				= list_ptr->tail_ptr;
	list_ptr->tail_ptr->prev	= node_ptr;

exit:
	if (error != mStatus_NoError && node_ptr != mDNSNULL) free(node_ptr);
	return error;
}

#pragma mark - list_prepend_uinitialized
mDNSexport mStatus
list_prepend_uinitialized(list_t * const _Nonnull list_ptr, const mDNSu32 new_data_size, void * _Nullable * _Nonnull out_data_ptr) {
	mStatus			error		= mStatus_NoError;
	list_node_t *	node_ptr	= mDNSNULL;
	list_node_t *	real_head	= mDNSNULL;

	require_action(list_ptr->data_size == new_data_size, exit, error = mStatus_BadParamErr);

	node_ptr = malloc(offsetof(list_node_t, data) + new_data_size);
	require_action(node_ptr != mDNSNULL, exit, error = mStatus_NoMemoryErr);

	*out_data_ptr = &node_ptr->data;

	real_head					= list_ptr->head_ptr->next;
	real_head->prev 			= node_ptr;
	node_ptr->next				= real_head;
	node_ptr->prev				= list_ptr->head_ptr;
	list_ptr->head_ptr->next	= node_ptr;

exit:
	if (error != mDNSNULL && node_ptr != mDNSNULL) free(node_ptr);
	return error;
}

#pragma mark - list_append_node
mDNSexport void
list_append_node(list_t * const _Nonnull list_ptr, list_node_t * const _Nonnull node_ptr) {
	node_ptr->prev					= list_ptr->head_ptr;
	node_ptr->next					= list_ptr->head_ptr->next;
	list_ptr->head_ptr->next->prev	= node_ptr;
	list_ptr->head_ptr->next		= node_ptr;
}

#pragma mark - list_prepend_node
mDNSexport void
list_prepend_node(list_t *const _Nonnull list_ptr, list_node_t * const _Nonnull node_ptr) {
	node_ptr->prev					= list_ptr->tail_ptr->prev;
	node_ptr->next					= list_ptr->tail_ptr;
	list_ptr->tail_ptr->prev->next	= node_ptr;
	list_ptr->tail_ptr->prev		= node_ptr;
}

#pragma mark - list_append_node_at_node
mDNSexport void
list_append_node_at_node(list_node_t * const _Nonnull original_node, list_node_t * const _Nonnull added_node) {
	list_node_t * const original_next = original_node->next;

	added_node->prev	= original_node;
	added_node->next	= original_next;
	original_node->next	= added_node;
	original_next->prev	= added_node;
}

#pragma mark - list_prepend_node_at_node
mDNSexport void
list_prepend_node_at_node(list_node_t * const _Nonnull original_node, list_node_t * const _Nonnull added_node) {
	list_node_t * const original_prev = original_node->prev;

	added_node->prev	= original_prev;
	added_node->next	= original_node;
	original_prev->next	= added_node;
	original_node->prev	= added_node;
}

#pragma mark - list_concatenate
mDNSexport void
list_concatenate(list_t * const _Nonnull dst_list, list_t * const _Nonnull src_list) {
	list_node_t *dst_last_node	= dst_list->tail_ptr->prev;
	list_node_t *src_first_node	= src_list->head_ptr->next;
	list_node_t *src_last_node	= src_list->tail_ptr->prev;

	if (list_empty(src_list)) {
		return;
	}

	src_list->head_ptr->next	= src_list->tail_ptr;
	src_list->tail_ptr->prev	= src_list->head_ptr;

	dst_last_node->next			= src_first_node;
	src_first_node->prev		= dst_last_node;
	src_last_node->next			= dst_list->tail_ptr;
	dst_list->tail_ptr->prev	= src_last_node;
}

#pragma mark - node_list_sort
mDNSlocal void
node_list_sort(list_node_t * _Nullable * const _Nonnull in_out_list_ptr, list_sort_comparator_t comparator);

#pragma mark - node_list_tail
mDNSlocal list_node_t *
node_list_tail(list_node_t * _Nonnull list_ptr);

#pragma mark - list_sort
mDNSexport void
list_sort(list_t * const _Nonnull list_ptr, list_sort_comparator_t comparator) {
	list_node_t *real_head = list_ptr->head_ptr->next;

	if (list_empty(list_ptr)) {
		return;
	}

	list_ptr->tail_ptr->prev->next	= mDNSNULL;
	list_ptr->head_ptr->next		= list_ptr->tail_ptr;
	list_ptr->tail_ptr->prev		= list_ptr->head_ptr;

	node_list_sort(&real_head, comparator);

	list_ptr->head_ptr->next		= real_head;
	list_ptr->tail_ptr->prev		= node_list_tail(real_head);
	real_head->prev 				= list_ptr->head_ptr;
	list_ptr->tail_ptr->prev->next	= list_ptr->tail_ptr;
}

#pragma mark - front_back_split
mDNSlocal void
front_back_split(list_node_t * const _Nonnull list_ptr, list_node_t **out_front, list_node_t **out_back);

#pragma mark - sorted_merge
mDNSlocal list_node_t *
sorted_merge(list_node_t * _Nullable left, list_node_t * _Nullable right, list_sort_comparator_t comparator);

#pragma mark - node_list_sort
mDNSlocal void
node_list_sort(list_node_t * _Nullable * const _Nonnull in_out_list_ptr, list_sort_comparator_t comparator) {
	list_node_t *list_ptr = *in_out_list_ptr;
	list_node_t *front_half;
	list_node_t *back_half;

	if (list_ptr == mDNSNULL || list_ptr->next == mDNSNULL)
		return;

	front_back_split(list_ptr, &front_half, &back_half);

	node_list_sort(&front_half, comparator);
	node_list_sort(&back_half, comparator);

	*in_out_list_ptr = sorted_merge(front_half, back_half, comparator);
}

#pragma mark - front_back_split
mDNSlocal void
front_back_split(
	list_node_t * const _Nonnull        list_ptr,
	list_node_t * _Nullable * _Nonnull  out_front,
	list_node_t * _Nullable * _Nonnull  out_back) {

	list_node_t *fast = list_ptr->next;
	list_node_t *slow = list_ptr;

	while (fast != mDNSNULL) {
		fast = fast->next;
		if (fast != mDNSNULL) {
			slow = slow->next;
			fast = fast->next;
		}
	}

	*out_front	= list_ptr;
	*out_back	= slow->next;
	slow->next	= mDNSNULL;
}

#pragma mark - sorted_merge
mDNSlocal list_node_t *
sorted_merge(list_node_t * _Nullable left, list_node_t * _Nullable right, list_sort_comparator_t comparator) {
	list_node_t *sorted_list;
	list_node_t *tail;
	mDNSs8 cmp_result;

	if (left == mDNSNULL) {
		return right;
	} else if (right == mDNSNULL) {
		return left;
	}

	cmp_result = comparator(left, right);
	if (cmp_result <= 0) {
		sorted_list = left;
		tail		= left;
		left		= left->next;
	} else {
		// cmp_result > 0
		sorted_list	= right;
		tail		= right;
		right		= right->next;
	}

	while (left != mDNSNULL && right != mDNSNULL) {
		cmp_result = comparator(left, right);
		if (cmp_result <= 0) {
			tail->next	= left;
			tail		= left;
			left		= left->next;
		} else {
			// cmp_result > 0
			tail->next	= right;
			tail		= right;
			right		= right->next;
		}
	}

	if (left != mDNSNULL) {
		tail->next = left;
	} else {
		tail->next = right;
	}

	return sorted_list;
}

#pragma mark - node_list_tail
mDNSlocal list_node_t *
node_list_tail(list_node_t * _Nonnull list_ptr) {
	while (list_ptr->next != mDNSNULL) {
		list_ptr = list_ptr->next;
	}

	return list_ptr;
}

#pragma mark - list_node_detach
mDNSexport void
list_node_detach(list_node_t * const _Nonnull node) {
	list_node_t *prev = node->prev;
	list_node_t *next = node->next;
	prev->next = next;
	next->prev = prev;
}

#pragma mark - list_node_delete
mDNSexport void
list_node_delete(list_node_t * const _Nonnull node_ptr) {
	list_node_t *prev;
	list_node_t *next;

	prev = node_ptr->prev;
	next = node_ptr->next;

	prev->next = next;
	next->prev = prev;

	free(node_ptr);
}

#pragma mark - list_node_delete_all
mDNSexport void
list_node_delete_all(list_t * const _Nonnull list_ptr) {
	list_node_t *next_node;
	for (list_node_t * node = list_get_first(list_ptr); !list_has_ended(list_ptr, node); node = next_node) {
		next_node = list_next(node);
		list_node_delete(node);
	}
}

#pragma mark - list_delete_node_with_data_ptr
mDNSexport mStatus
list_delete_node_with_data_ptr(list_t * const _Nonnull list_ptr, void * const _Nonnull data) {
	mStatus error = mStatus_NoSuchKey;

	for (list_node_t *ptr = list_get_first(list_ptr); !list_has_ended(list_ptr, ptr); ptr = list_next(ptr)) {
		if (data == &ptr->data) {
			list_node_delete(ptr);
			error = mStatus_NoError;
			break;
		}
	}

	return error;
}

#pragma mark - list_empty
mDNSexport mDNSBool
list_empty(const list_t * const _Nonnull list_ptr) {
	return list_ptr->head_ptr->next == list_ptr->tail_ptr;
}

#pragma mark - list_count_node
mDNSexport mDNSu32
list_count_node(const list_t *const _Nonnull list_ptr) {
	mDNSu32 count = 0;

	if (list_empty(list_ptr)) {
		return 0;
	}

	for (list_node_t *ptr = list_get_first(list_ptr); !list_has_ended(list_ptr, ptr); ptr = list_next(ptr)) {
		count++;
	}

	return count;
}

#pragma mark - list_get_first
mDNSexport list_node_t * _Nullable
list_get_first(const list_t * const _Nonnull list_ptr) {
	if (list_empty(list_ptr)) {
		return mDNSNULL;
	}

	return list_ptr->head_ptr->next;
}

#pragma mark - list_get_last
mDNSexport list_node_t * _Nullable
list_get_last(const list_t * const _Nonnull list_ptr) {
	if (list_empty(list_ptr)) {
		return mDNSNULL;
	}

	return list_ptr->tail_ptr->prev;
}

#pragma mark - list_next
mDNSexport list_node_t * _Nonnull
list_next(const list_node_t * const _Nonnull node_ptr) {
	return node_ptr->next;
}

#pragma mark - list_has_ended
mDNSexport mDNSBool
list_has_ended(const list_t * const _Nonnull list_ptr, const list_node_t * const _Nullable node_ptr) {
	if (node_ptr == mDNSNULL) {
		return mDNStrue;
	}
	return node_ptr == list_ptr->tail_ptr;
}

#pragma mark - list_uninit
mDNSexport void
list_uninit(list_t * const _Nonnull list_ptr) {
	list_node_delete_all(list_ptr);

	list_ptr->data_size			= 0;
	list_ptr->head_ptr->next	= mDNSNULL;
	list_ptr->tail_ptr->prev	= mDNSNULL;
	list_ptr->head_ptr			= mDNSNULL;
	list_ptr->tail_ptr			= mDNSNULL;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
