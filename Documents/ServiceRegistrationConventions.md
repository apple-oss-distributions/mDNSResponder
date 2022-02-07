## Reference counting

The code has been moving towards reference counting; this migration is incomplete, and some objects are still managed explicitly. The conventions for reference counting have been evolving, and so not all reference-counted objects are handled in a completely uniform way. The way reference counted objects should work is as follows:

### No implicit reference counts.
Every reference held should be counted, and released when the object is no longer referenced. So e.g. if network framework has a reference to the object because it's in-scope for a block invocation, that reference should be released in the block only for the cancel event handler. Network framework will always call the cancel event handler last.

Similarly, if a refcounted object holds a reference to another refcounted object, then that object should be given a callback to call to dereference the object for which the reference has been held. See for example ioloop_dnssd_txn_add in ioloop.c, which creates a reference for the file descriptor object that is used to manage I/O events for that DNSSD transaction.

This can be really tricky, so be careful. E.g., look at udp_start() in macos-ioloop.c. This function retains the connection object before calling nw_connection_receive_message. The invoked block then conditionally calls udp_start(), which will hold a new reference to the connection object; the old reference is then unconditionally dropped. This ensures that we always have a reference if we might get a callback, but that we always drop the reference we held for the previous callback, so that when the UDP "connection" is terminated, we don't leak.

The way this should look is that when the object for which the reference has been held is no longer needed, it sticks around and is still valid until the finalize callback for the object that referenced it is called; that callback winds up actually releasing the object. This avoids us getting a callback of some other kind from the referencing object that references the no-longer-in-use object and triggers some store or reference into that object after it has been freed. Beware, of course, that this means that such callbacks need to behave correctly when the object is no longer active. There are lots of examples of this in the code.

### Mechanics of refcounting

Objects can be retained with the RETAIN_HERE and RETAIN macros.  When we are spewing debug logging messages, every release and retain emits a log message with the file and line number at which the retain or release happened. RETAIN_HERE reports the current file and line. RETAIN looks for a variable in scope named "file" that's const char *, and a variable in scope named "line" that's int, and uses those to report the file and line number. This can be helpful to differentiate between multiple releases of an object when debugging. So e.g. a lot of _create() functions take a file and line variable, and have a macro in the header in which they are declared that makes this automatic.

The RELEASE_HERE and RELEASE macros behave similarly, except that the invocation includes the finalize function to call if the refcount goes to zero.

Generally speaking, these should only be used for objects that are not opaque to the local file. There's no enforcement of opaqueness, but often the finalize function is file-local, which effectively enforces this. So many objects have _create(), _retain() and _release() functions that create, retain and release them. These functions generally have macros that supply the file and line variables, so that the place where the function is invoked is logged rather than the location in the function where the retain or release happens.

The code should be following the [create/copy rule](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MemoryMgmt/Articles/mmRules.html). Obviously there is no autorelease capability.

Objects that are refcounted have an integer member named "ref_count" which is set to one when the object is created. This need not be in any particular order within the C struct that represents the object.

### Refcounting function signatures

*Note:* the finalize_callback_t function actually releases the _context_ pointer. It would be easy to be confused by this name, and we should probably change finalize_callback_t finalize to release_callback_t context_release.

#### `xxx_create(<initialization data>, void *context, finalize_callback_t finalize)`
Every reference counted object should have an _xxx_create_ function. This function will include some data that is required to initialize the object, a context that will be passed to any callback that is called by the function, and a finalize function that's called in the _xxx_finalize_ function for the object that releases the object's reference to _context_. The object returned by the create function is returned with a reference count of 1.

For example, _ioloop_file_descriptor_create(int fd, void *context, finalize_callback_t finalize)_. The file descriptor object is a specialization of the _io_t_ object. There is no callback other than the finalize callback specified in the create function. To track reads on the file descriptor, _ioloop_add_reader_ is called. Similarly for write events, _ioloop_add_writer_ is called. Both functions take a callback, which is called with the context passed to _ioloop_file_descriptor_create_.

If _context_ is not null, and is an object that might be freed, that object must support reference counting, and its _xxx_retain_ function should be called when passing it to the _ioloop_file_descriptor_create_ function. When invoking _ioloop_file_descriptor_create_ in this way, the caller must pass a callback in the _finalize_callback_ argument. When the file descriptor object's reference count reaches zero, the finalize callback will be invoked. This callback must then call the _xxx_release_ function for the object to which the _context_ argument points. This releases the reference that was being held by the file descriptor object.

#### `xxx_retain(object)`
This function is only present for objects that are exported. For such objects, the _xxx_retain_ function simply increases its reference count by one. xxx_retain functions are not required for objects that are only in scope for an individual source file. In this case, the _RETAIN_ and _RETAIN_HERE_ macros can be used instead.

#### `xxx_release(object)`
This function is only present for objects that are exported. For such objects, the _xxx_release_ function decreases its reference count by one. If the object's reference count goes to zero, the object's finalize function is called. xxx_release functions are not required for objects that are only in scope for an individual source file. In this case, the _RELEASE_ and _RELEASE_HERE_ macros can be used instead.

#### `xxx_finalize(object)`
This function is generally not exported, because it is invoked implicitly when the object's reference count goes to zero as a result of a call to the _xxx_release_ function. The finalize function is responsible for freeing all memory associated with the object, and releasing any references held by the object. This function must not be called if there are still outstanding events that could be delivered to the object. The finalize function for an object typically calls the finalize callback for the _context_ that was given to the object, if any.

#### `xxx_cancel(object)`
An object may have some asynchronous actions that invoke callbacks on it. For example, an object might have a read callback which is called whenever there is data available to read on the file descriptor that the object represents. The _xxx_cancel_ function cancels any such future events.

It is possible that when _xxx_cancel_ is invoked, some events have already been queued, such that the callbacks for those events will be called even though future such events have been canceled. The point of the _xxx_cancel_ function is to make sure that the object is not finalized until all of those events have been delivered and no further events are queued.

The object is responsible for managing this: for knowing whether any events could be outstanding, and for coming to a decision that definitely no further events are outstanding. In order to prevent the object being finalized before such outstanding events have completed, the object must retain a reference to itself for those events. When the object implementation knows that no further events will be delivered, this reference can be released.

For example, the ioloop file descriptor object can have outstanding read and write events. When either a read or write event subscription is added, the file descriptor reference count is increased by one. When the cancel event is called, one of two things may happen. If the implementation is able to conclude that no further events will be delivered, it may release that reference before returning.

However, depending on the underlying implementation, this may not be possible. In this second case, an event delivered to the underlying implementation will indicate that no further events can be delivered. During the handling of this event, the reference count is released.

Because the event reference to the object can be released either within the _xxx_cancel_ function, or later on in the event loop after the _xxx_cancel_ function has returned, the caller to _xxx_cancel_ can't make any assumptions about when the release will actually happen.

For objects such as _comm_t_, which on the Mac uses _nw_connection_t_ or _nw_listener_t_, the call to _ioloop_comm_cancel_ calls _nw_connection_cancel_ to trigger a shutdown process which is ultimately guaranteed to deliver an _nw_connection_state_cancelled_ event to the _nw_connection_t_'s event handler block, which is part of the implementation for the _comm_t_ object on Mac. This event is guaranteed to be the last event delivered to the event handler block, so at this point the event handler block can safely release its reference to the _comm_t_ object. You can see this behavior in the _connection_state_changed_ function in macos-ioloop.c, which implements the _nw_connection_t_ event handler for _comm_t_ objects.

It is possible for the _xxx_cancel_ function to be called after the event reference has been released. This can happen, for example with _nw_connection_t_, when the connection is closed by the remote end. In this case the _nw_connection_t_ object may deliver a cancel event as a result of actions taken in the event handler. In this case whatever function invokes _xxx_cancel_ is also holding a reference count to the object, so the object is still valid. The _xxx_cancel_ function must detect this situation and return without taking any action.

This can often be accomplished by releasing the wrapped object (e.g. _nw_connection_t_ in the above example) and setting the pointer from the enclosing object (_comm_t_ in the above example) to NULL. When _ioloop_comm_cancel_ is called on an object where the internal pointer to the _nw_connection_t_ is NULL, _ioloop_comm_cancel_ simply returns.

If you read through the code that uses _xxx_cancel_ functions, you'll find that these functions are often used when context is provided in the corresponding _xxx_create_ function, but without a finalize callback being provided. The reason for this is that sometimes the cancel can be done synchronously, such that we know no further events will happen. In this case, context will never be used after the call to cancel, so there's no need to hold a reference for the event, and it's safe to release the final reference to the object immediately after calling cancel. The mere fact that this flow is common in the code should not be taken to mean that it's always okay to release the last reference immediately after calling cancel.

Examples of this flow working include wakeup timers, which can be immediately canceled on both Mac and POSIX, and _dnssd_txn_t objects, where the underlying object (DNSServiceRef) is not refcounted and is guaranteed not to deliver events after DNSServiceRefDealloc has been called.

#### `RETAIN(object)`
#### `RETAIN_HERE(object)`
For objects that are used within a single module, two macros, _RETAIN_ and _RETAIN_HERE_, can be used to retain a reference to the object. These assume that the structure being retained has a member named _ref_count_ which is the reference count for the structure. Both macros increment _ref_count_ by one. _RETAIN_ looks for a `char *file` variable that indicates the filename of the function responsible for this retain, and an `int line` variable that indicates the file line number. _RETAIN_HERE_ uses `__FILE__` and `__LINE__`. Both functions, when enabled, log the retain for debugging purposes.

#### `RELEASE(object, finalize_function)`
#### `RELEASE_HERE(object, finalize_function)`
For objects that are used within a single module, two macros, _RELEASE_ and _RELEASE_HERE_, can be used to release references to the object. These assume that the structure being released has a member named _ref_count_ which is the reference count for the structure. Both macros decrement _ref_count_ by one. If ref_count is zero after decrementing, _finalize_function_ is invoked with a single argument, the pointer to the object, which is then finalized.

_RELEASE_ looks for a `char *file` variable that indicates the filename of the function responsible for this retain, and an `int line` variable that indicates the file line number. _RELEASE_HERE_ uses `__FILE__` and `__LINE__`. Both functions, when enabled, log the release for debugging purposes.

## Explicitly managed objects

Objects are always zeroed when allocated, with the exception of objects like allocated strings that are initialized upon allocation, either with strdup or memcpy. Explicitly managed objects are often created in a specific place, but (unless they can be freed directly) should have a _free() function that frees any additional memory associated with them. Before refcounting was added to the code, some such functions were actually called _finalize(). This is not correct, and we should migrate away from that over time, or else refcount such objects.
