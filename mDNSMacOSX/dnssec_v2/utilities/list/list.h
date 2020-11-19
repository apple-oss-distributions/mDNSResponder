//
//  list.h
//  mDNSResponder
//
//  Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef LIST_H
#define LIST_H

#pragma mark - Includes
#include <stdint.h>
#include <stdio.h>
#include <AssertMacros.h>       // for require_* macro
#include "mDNSEmbeddedAPI.h"    // for mStatus
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)

#pragma mark - Structures



#pragma mark list_node_t
/*!
 * 	@brief
 *		A node in the list_t.
 */
typedef struct list_node list_node_t;
struct list_node {
	list_node_t *	_Nullable	prev;
	list_node_t *	_Nullable	next;
	mDNSu8						data[0];	// the actual data will be stored starting from data, so list_node_t->data can access it
};

#pragma mark list_t
/*!
 * 	@brief
 *		A structure that represents a generic doublely linked list.
 */
typedef struct list list_t;
struct list {
	mDNSu32						data_size;	// to check if the data put into the list matches the size of actual structure
	list_node_t *	_Nullable	head_ptr;
	list_node_t *	_Nullable	tail_ptr;
	list_node_t					head;		// dummy head will be pointed by head_ptr
	list_node_t					tail;		// dummy tail will be pointed by tail_ptr
};

#pragma mark - Functions



#pragma mark list_init
/*!
 *	@brief
 *		Initializes list_t, must be called before using the list
 *
 *	@param list_to_init
 *		The pointer to the unintialized list
 *
 *	@param new_data_size
 *		the size of the data that will be put into the list
 *
 *	@discussion
 *		After the list is initialized with "new_data_size", we could only put the same data structure that has the same "data_size" into the list
 */
mDNSexport void
list_init(list_t * const _Nonnull list_to_init, const mDNSu32 new_data_size);

#pragma mark list_append_uinitialized
/*!
 *	@brief
 *		Appends a node at the end of the list, and return a memory pointer that can be used to store the data structure.
 *
 *	@param list_ptr
 *		The pointer to the list.
 *
 *	@param new_data_size
 *		The size of the data structure that will be appended into the list.
 *
 *	@param out_data_ptr
 *		The output pointer to the memory location that can be used to save the data structure.
 *
 *	@return
 *		mStatus_NoError if everything works fine, or other error codes defined in mStatus.

 *	@discussion
 *		The returned memory pointer can be used to initialize a data structure which will stored in the list.
 */
mDNSexport mStatus
list_append_uinitialized(list_t * const _Nonnull list_ptr, const mDNSu32 new_data_size, void * _Nullable * _Nonnull out_data_ptr);

#pragma mark list_prepend_uinitialized
/*!
 *	@brief
 *		Prepends a node at the start of the list, and return a memory pointer that can be used to store the data structure.
 *
 *	@param list_ptr
 *		The pointer to the list.
 *
 *	@param new_data_size
 *		The size of the data structure that will be appended into the list.
 *
 *	@param out_data_ptr
 *		The output pointer to the memory location that can be used to save the data structure.
 *
 *	@return
 *		mStatus_NoError if everything works fine, or other error codes defined in mStatus.

 *	@discussion
 *		The returned memory pointer can be used to initialize a data structure which will be stored in the list.
 */
mDNSexport mStatus
list_prepend_uinitialized(list_t * const _Nonnull list_ptr, const mDNSu32 new_data_size, void * _Nullable * _Nonnull out_data_ptr);

#pragma mark list_append_node
/*!
 *	@brief
 *		Given a list_node_t structure, insert it in the end of the list.
 *	@param list_ptr
 *		The pointer to the list.
 *	@param node_ptr
 *		The list_node_t structure to be inserted.
 */
mDNSexport void
list_append_node(list_t * const _Nonnull list_ptr, list_node_t * const _Nonnull node_ptr);

/*!
 *	@brief
 *		Given a list_node_t structure, insert it in the start of the list.
 *	@param list_ptr
 *		The pointer to the list.
 *	@param node_ptr
 *		The list_node_t structure to be inserted.
 */
#pragma mark list_prepend_node
mDNSexport void
list_prepend_node(list_t * const _Nonnull list_ptr, list_node_t * const _Nonnull node_ptr);

#pragma mark list_append_node_at_node
/*!
 *	@brief
 *		Append the list_node_t after the given node in the list
 *	@param original_node
 *		The node to be appended after.
 *	@param added_node
 *		The node to append.
 */
mDNSexport void
list_append_node_at_node(list_node_t * const _Nonnull original_node, list_node_t * const _Nonnull added_node);

#pragma mark list_prepend_node_at_node
/*!
 *	@brief
 *		Prepend the list_node_t before the given node in the list
 *	@param original_node
 *		The node to be appended after.
 *	@param added_node
 *		The node to prepend.
 */
mDNSexport void
list_prepend_node_at_node(list_node_t * const _Nonnull original_node, list_node_t * const _Nonnull added_node);

#pragma mark list_concatenate
/*!
 *	@brief
 *		Concatenate two lists together.
 *	@param dst_list
 *		The list to concatenate with.
 *	@param src_list
 *		The list to concatenate with.
 *	@discussion
 *		The concatenation result is the dst_list.
 */
mDNSexport void
list_concatenate(list_t * const _Nonnull dst_list, list_t * const _Nonnull src_list);

#pragma mark list_sort_comparator_t
/*!
 *	@brief
 *		The sort comparator for the list.
 *	@param left
 *		The list_node_t to be compared.
 *	@param right
 *		The list_node_t to be compared.
 *	@discussion
 *		If the comparator returns -1, 0 and 1, -1 means left is less than right, 0 means left is equal to right, 1 means left is greater than right
 */
typedef mDNSs8 (* _Nonnull list_sort_comparator_t)(const list_node_t * _Nonnull const left, const list_node_t * _Nonnull const right);

#pragma mark list_sort
/*!
 *	@brief
 *		Sort the node in the list according to the comparator.
 *	@param list_ptr
 *		The list to be sorted.
 *	@param comparator
 *		The list_sort_comparator_t that defines the sort order.
 *	@discussion
 *		If the comparator returns -1, 0 and 1, -1 means left is less than right, 0 means left is equal to right, 1 means left is greater than right
 */
mDNSexport void
list_sort(list_t * const _Nonnull list_ptr, list_sort_comparator_t comparator);

#pragma mark list_node_detach
/*!
 *	@brief
 *		Detach the list_node_t from the list
 *	@param node
 *		The node to be detached
 *	@discussion
 *		It will only seperate the node from the list,  the node itself still exists.
 */
mDNSexport void
list_node_detach(list_node_t * const _Nonnull node);

#pragma mark list_node_delete
/*!
 *	@brief
 *		Delete the current node that is in the list.
 *	@param node_ptr
 *		The pointer of the node to be deleted.
 *	@discussion
 *		This function must be used for the node that is in the list.
 */
mDNSexport void
list_node_delete(list_node_t * const _Nonnull node_ptr);

#pragma mark list_node_delete_all
/*!
 *	@brief
 *		Delete all nodes in the list
 *	@param list_ptr
 *		The pointer to the list.
 */
mDNSexport void
list_node_delete_all(list_t * const _Nonnull list_ptr);

#pragma mark list_delete_node_with_data_ptr
/*!
 *	@brief
 *		Delete the node in the list that contains the data.
 *	@param list_ptr
 *		The pointer to the list that will delete the node.
 *	@param data
 *		The pointer to the data that one node in list contains.
 *	@return
 *		return mStatus_NoError if the node is found and deleted from the list, return mStatus_NoSuchKey if the node does not exist.
 *	@discussion
 *		The function will scan through the list, compare the data field of node with the "data" parameter.
 */
mDNSexport mStatus
list_delete_node_with_data_ptr(list_t * const _Nonnull list_ptr, void * const _Nonnull data);

#pragma mark list_empty
/*!
 *	@brief
 *		Test if the list is empty or not.
 *	@param list_ptr
 *		The list to test.
 *	@return
 *		Returns true if the lis is empty, returns false if the list has nodes inside.
 */
mDNSexport mDNSBool
list_empty(const list_t * const _Nonnull list_ptr);

#pragma mark list_count_node
/*!
 *	@brief
 *		Get the number of nodes in the list.
 *	@param list_ptr
 *		The list to count node.
 *	@return
 *		The number of nodes.
 */
mDNSexport mDNSu32
list_count_node(const list_t *const _Nonnull list_ptr);

#pragma mark list_get_first
/*!
 *	@brief
 *		Get the first node in the list.
 *	@param list_ptr
 *		The pointer to the list.
 *	@return
 *		The first list_node_t in the list, if the list is empty, NULL is returned.
 */
mDNSexport list_node_t * _Nullable
list_get_first(const list_t * const _Nonnull list_ptr);

#pragma mark list_get_last
/*!
 *	@brief
 *		Get the last node in the list.
 *	@param list_ptr
 *		The pointer to the list.
 *	@return
 *		The last list_node_t in the list, if the list is empty, NULL is returned.
 */
mDNSexport list_node_t * _Nullable
list_get_last(const list_t * const _Nonnull list_ptr);

#pragma mark list_next
/*!
 *	@brief
 *		Get the next node of the current node in the list.
 *	@param node_ptr
 *		The pointer to the current node.
 *	@return
 *		The next node.
 */
mDNSexport list_node_t * _Nonnull
list_next(const list_node_t * const _Nonnull node_ptr);

#pragma mark list_has_ended
/*!
 *	@brief
 *		Test if the current node has reached the end of the list.
 *	@param list_ptr
 *		The pointer to the list.
 *	@param node_ptr
 *		The pointer to the node.
 *	@return
 *		Returns true if the node_ptr points to the end of the list, returns false if it has more nodes coming next.
 */
mDNSexport mDNSBool
list_has_ended(const list_t * const _Nonnull list_ptr, const list_node_t * const _Nullable node_ptr);

#pragma mark list_uninit
/*!
 *	@brief
 *		Delete all the existing nodes in the list, and untialize the list structure.
 *	@param list_ptr
 *		The pointer to the list that will be uninitialized.
 */
mDNSexport void
list_uninit(list_t * const _Nonnull list_ptr);

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#endif // LIST_H
