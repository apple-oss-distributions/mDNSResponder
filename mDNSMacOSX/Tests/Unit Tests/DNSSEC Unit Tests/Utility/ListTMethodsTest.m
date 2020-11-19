//
//	ListTMethodsTest.m
//	Tests
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#import <XCTest/XCTest.h>
#include "list.h"
#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)

typedef struct test_struct_t {
	mDNSu8	field_one;
	mDNSu32 field_two;
} test_struct_t;

@interface ListTMethodsTest : XCTestCase

@end

@implementation ListTMethodsTest

- (void)testListInitAndUninit{
	list_t list;

	list_init(&list, sizeof(test_struct_t));
	XCTAssertEqual(list.head_ptr,		&list.head,				@"list.head_ptr should point to list.head");
	XCTAssertEqual(list.tail_ptr,		&list.tail,				@"list.tail_ptr should point to list.tail");
	XCTAssertEqual(list.head_ptr->next, list.tail_ptr,			@"The next node of head should be tail");
	XCTAssertEqual(list.tail_ptr->prev, list.head_ptr,			@"The previous node of tail should be head");
	XCTAssertEqual(list.data_size,		sizeof(test_struct_t),	@"The data size should be sizeof(test_struct_t)");

	list_uninit(&list);
	XCTAssertEqual(list.data_size, 0,			@"The data size should be 0");
	XCTAssertNil((__bridge id)list.head.next,	@"The next node of head should be NULL");
	XCTAssertNil((__bridge id)list.tail.prev,	@"The previous node of tail should be NULL");
	XCTAssertNil((__bridge id)list.head_ptr,	@"The head pointer should point to NULL");
	XCTAssertNil((__bridge id)list.tail_ptr,	@"The tail pointer should point to NULL");
}

- (void)testListGeneralOperation{
	mStatus error;
	list_t	list;
	mDNSBool empty;
	mDNSu8 count;
	test_struct_t *append_node_data_1, *append_node_data_2, *prepend_node_data_1, *prepend_node_data_2;
	list_node_t *first_node, *second_node, *third_node, *fourth_node;

	// Initialize
	list_init(&list, sizeof(test_struct_t));

	// Get first and last for empty list
	XCTAssertNil((__bridge id)list_get_first(&list));
	XCTAssertNil((__bridge id)list_get_last(&list));

	// Append succeeds
	error = list_append_uinitialized(&list, sizeof(test_struct_t), (void **)&append_node_data_1);
	XCTAssertEqual(error, mStatus_NoError, @"list_append_uinitialized failed; error_description='%s'", mStatusDescription(error));
	first_node = list.head_ptr->next;
	XCTAssertEqual(first_node->prev, list.head_ptr,			@"The first node should point to head");
	XCTAssertEqual(first_node->next, list.tail_ptr,			@"The next of first node should point to tail");
	XCTAssertEqual(list.tail_ptr->prev, first_node,			@"The previous of tail should point to first node");
	XCTAssertEqual((void *)first_node->data, (void *)append_node_data_1, @"The data field should be equal to the returned data pointer");

	// Get first and last
	XCTAssertEqual(list_get_first(&list),	first_node);
	XCTAssertEqual(list_get_last(&list),	first_node);

	// Append fails
	error = list_append_uinitialized(&list, sizeof(test_struct_t) - 1, (void **)&append_node_data_2);
	XCTAssertEqual(error, mStatus_BadParamErr, @"List should not add new node since the type of embedded data does not match");

	// Empty test
	empty = list_empty(&list);
	XCTAssertFalse(empty, @"List should not be empty");

	// Count test
	count = list_count_node(&list);
	XCTAssertEqual(count, 1, @"There should be only 1 node");

	// Append 2nd succeeds
	error = list_append_uinitialized(&list, sizeof(test_struct_t), (void **)&append_node_data_2);
	XCTAssertEqual(error, mStatus_NoError, @"list_append_uinitialized failed; error_description='%s'", mStatusDescription(error));
	second_node = list.tail_ptr->prev;
	XCTAssertEqual(first_node->next,			second_node);
	XCTAssertEqual(first_node->prev,			list.head_ptr);
	XCTAssertEqual(first_node->next,			second_node);
	XCTAssertEqual(second_node->next,			list.tail_ptr);
	XCTAssertEqual(second_node->prev,			first_node);
	XCTAssertEqual((void *)second_node->data,	(void *)append_node_data_2);

	// Count test
	count = list_count_node(&list);
	XCTAssertEqual(count, 2);

	// Get first and last
	XCTAssertEqual(list_get_first(&list),	first_node);
	XCTAssertEqual(list_get_last(&list),	second_node);

	// Prepend 3rd succeeds
	error = list_prepend_uinitialized(&list, sizeof(test_struct_t), (void **)&prepend_node_data_1);
	XCTAssertEqual(error, mStatus_NoError);
	third_node = list.head_ptr->next;
	XCTAssertEqual(third_node->next,			first_node);
	XCTAssertEqual(third_node->prev,			list.head_ptr);
	XCTAssertEqual(first_node->prev,			third_node);
	XCTAssertEqual((void *)third_node->data,	(void *)prepend_node_data_1);

	// Count test
	count = list_count_node(&list);
	XCTAssertEqual(count, 3);

	// Get first and last
	XCTAssertEqual(list_get_first(&list),	third_node);
	XCTAssertEqual(list_get_last(&list),	second_node);

	// Prepend fails
	error = list_prepend_uinitialized(&list, sizeof(test_struct_t) - 1, (void **)&prepend_node_data_2);
	XCTAssertEqual(error, mStatus_BadParamErr);

	// Preopend 4th succeeds
	error = list_prepend_uinitialized(&list, sizeof(test_struct_t), (void **)&prepend_node_data_2);
	XCTAssertEqual(error, mStatus_NoError);
	fourth_node = list.head_ptr->next;
	XCTAssertEqual(fourth_node->next,			third_node);
	XCTAssertEqual(fourth_node->prev,			list.head_ptr);
	XCTAssertEqual(third_node->prev,			fourth_node);
	XCTAssertEqual((void *)fourth_node->data,	(void *)prepend_node_data_2);

	// Count test
	count = list_count_node(&list);
	XCTAssertEqual(count, 4);

	// Get first and last
	XCTAssertEqual(list_get_first(&list),	fourth_node);
	XCTAssertEqual(list_get_last(&list),	second_node);

	// Iteration test
	for (list_node_t *node = list_get_first(&list); !list_has_ended(&list, node); node = list_next(node)) {
		if (node == first_node) {
			XCTAssertEqual((void *)node->data, (void *)append_node_data_1);
		} else if (node == second_node) {
			XCTAssertEqual((void *)node->data, (void *)append_node_data_2);
		} else if (node == third_node) {
			XCTAssertEqual((void *)node->data, (void *)prepend_node_data_1);
		} else if (node == fourth_node) {
			XCTAssertEqual((void *)node->data, (void *)prepend_node_data_2);
		} else {
			XCTAssertTrue(mDNSfalse, @"Unknown node added into the list");
		}
	}

	// Delete one node with node pointer
	list_node_delete(first_node);
	XCTAssertEqual(third_node->next,		second_node);
	XCTAssertEqual(third_node->prev,		fourth_node);
	XCTAssertEqual(second_node->prev,		third_node);
	XCTAssertEqual(list_count_node(&list),	3);
	XCTAssertFalse(list_empty(&list));

	// Delete one node with data pointer that exists
	error = list_delete_node_with_data_ptr(&list, prepend_node_data_2);
	XCTAssertEqual(error, mStatus_NoError);
	XCTAssertEqual(list_get_first(&list),	third_node);
	XCTAssertEqual(list_get_last(&list),	second_node);
	XCTAssertEqual(third_node->next,		second_node);
	XCTAssertEqual(third_node->prev,		list.head_ptr);
	XCTAssertEqual(second_node->next,		list.tail_ptr);
	XCTAssertEqual(list_count_node(&list),	2);
	XCTAssertFalse(list_empty(&list));

	// Delete one node with data pointer that does not exist
	error = list_delete_node_with_data_ptr(&list, prepend_node_data_2 + 1);
	XCTAssertEqual(error,					mStatus_NoSuchKey);
	XCTAssertEqual(list_get_first(&list),	third_node);
	XCTAssertEqual(list_get_last(&list),	second_node);
	XCTAssertEqual(third_node->next,		second_node);
	XCTAssertEqual(third_node->prev,		list.head_ptr);
	XCTAssertEqual(second_node->next,		list.tail_ptr);
	XCTAssertEqual(list_count_node(&list),	2);
	XCTAssertFalse(list_empty(&list));

	// Delete all the nodes
	list_node_delete_all(&list);

	// Count test
	count = list_count_node(&list);
	XCTAssertEqual(count, 0);

	// Empty test
	empty = list_empty(&list);
	XCTAssertTrue(empty);

	// Iterate through the empty list
	for (list_node_t *node = list_get_first(&list); !list_has_ended(&list, node); node = list_next(node)) {
		XCTAssertFalse(mDNStrue, @"Should never excute this line if the line is empty");
	}

	// uninitialize the list
	list_uninit(&list);
	XCTAssertEqual(list.data_size, 0);
	XCTAssertNil((__bridge id)list.head.next);
	XCTAssertNil((__bridge id)list.tail.prev);
	XCTAssertNil((__bridge id)list.head_ptr);
	XCTAssertNil((__bridge id)list.tail_ptr);
}
@end

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
