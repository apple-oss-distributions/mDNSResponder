# How mDNSResponder handles time

mDNSResponder has to keep track of time so that events happen when they need to happen: cache entries expire when the TTL says they are going to expire, retransmissions occur when they should, and so on. However, mDNSResponder generally does not need to know what the actual wall clock time is.

mDNSResponder tracks the current time in, e.g., the variable `m->timenow`. This isn't based on any particular reference time (boot time, 1970-01-01, etc.). Its value taken by itself is meaningless. The only thing that matters is that it increases at a steady rate. m->timenow is only useful when comparing it to other time values to tell if that other time value is in the past, present, or future.

For example, say that I have a watch that isn't synchronized to any world clock. Let's say the UTC time is currently 12:00:00, but my watch says the current time is 07:13:12, and say I'm not aware of the offset from the UTC time. This watch is obviously not good for telling the "real" current time because it isn't synchronized to any world clock.

But so long as the watch is precise, I can set an alarm for 07:14:42 if I want to be notified when 90 seconds have passed. Or I can set the alarm for 08:13:12, if I want to be notified when one hour has passed, etc. As another example, if I make a note that I woke up today at 04:11:21, then I know that I woke up approximately three hours ago. So the watch is still useful for measuring elapsed time.

The unsynchronized watch example is similar to how mDNSResponder uses `m->timenow`. If we want something to happen in one hour, then we set an alarm for `m->timenow + 3600 * mDNSPlatformOneSecond` (on Apple platforms this would be 3600000). As another example, if I have a time variable called expiration for when an item is supposed to be considered expired, and `expiration - m->timenow <= 0`, then I know that the item has expired. On the other hand, if `expiration - m->timenow > 0`, then the expiration time is in the future, i.e., the item has not yet expired.

## Two's complement math

The reason this computation works the way it does is that we are doing two's complement math on a 32-bit integer. Think of the wall clock example: if I subtract 11pm from 1am, the difference is two hours, right? That's a positive answer: 1am is later than 11pm. If I subtract 1am from 11pm, I get negative two hours, because 1am is later than (greater than) 11pm.

When doing two's complement math, this clock-like overflow works the same way. To see how this works, let's try it with 8-bit numbers, since they're a bit more manageable. An 8-bit signed two's complement number can have any value in the range [-128,127]. So suppose we remember a clock time of 126 (nearly the largest wall clock time possible with 8 bits). And then later we check the clock time again, and it's now -124. We can't just compare these times, because the clock has wrapped to the next day: -124 is later than 126, but `-124 > 126` evaluates to false, which is the wrong result.

So we can't compare--we have to subtract. In two's complement math, the computation `-124 - 126` _underflows_, producing a result of 6, which is a positive number. So `-124 - 126 > 0` in 8-bit two's complement math.

What this kind of math can't account for are differences of greater than half the maximum time range on the clock. On the 8-bit two's complement clock, we could say that midnight is 0, and the tick before midnight is -128. 6 on the clock dial would be halfway between 127 and 128. So if we record the wall clock time, wait a little over six hours, and then record it again, we have no way to tell which order the two recorded events occurred in, unless we just know. The two's complement comparison method we are using only works for periods of less than half the range--for 8 bits this would be periods of less than 128 ticks. Any period longer than that will produce an incorrect output from the comparison.

In mDNSResponder we use 32 bits, so half the range is INT32_MAX (2 << 31). This is a bit more comfortable: on Apple platforms that's a bit more than 24 days. mDNSResponder can never reason about time intervals longer than 24 days (on Apple platforms, remember). mDNSResponder uses the constant FutureTime to mean "about as far in the future as is possible to measure." This value is a bit over ten days if mDNSPlatformOneSecond is 1000. FutureTime is represented in ticks, so if mDNSPlatformOneSecond were 100 instead of 1000, FutureTime would be more than 100 days.

To summarize, in order to compare two time values, `time1` and `time2`, in mDNSResponder: use `if (time1 - time2 > 0)` and not `if (time1 > time2)`.


## Using zero to mean "no timeout"

There are a number of places in mDNSResponder where we record a time, but we also want to be able to indicate that the recorded time is null--that this particular timer hasn't been set and shouldn't go off. We use the value zero to indicate this. So when we are computing a time in the future, we can use the macro NonZeroTime() to ensure that the computation is always nonzero. If `m->timenow + interval` is exactly zero, `NonZeroTime(m->timenow + interval)` returns 1. This is close enough to the intended time not to cause a problem, and lets us treat zero as "no time recorded".

## m->timenow is randomized on startup

The initial value of `m->timenow` is deliberately randomized. This is done because we know that there is the possibility that we might get some time calculation wrong in a way that will only be detected when the timer wraps. If the timer always starts at zero, then this will only happen on devices that have been up and running for a long time, which means that a serious problem might only actually be seen rarely, and therefore would be hard to track down.

By randomizing the time, we ensure that such a problem will be detected as quickly as possible on some hosts, meaning that we should see a steady stream of bug reports for the problem instead of a very occasional report. The reason for randomizing rather than setting the initial time to `INTMAX - K` is that there's no value of `K` we could choose that would maximize the likelihood of detecting this unknown failure. By randomizing, we maximize the chance that the failure will occur as quickly as possible on some devices.

## The duration of a tick is platform-dependent

`m->timenow` is a 32-bit signed integer. The amount of time represented by each tick (each increment of one) is platform dependent. To translate ticks into real time, multiply seconds by mDNSPlatformOneSecond. On Mac, the value of mDNSPlatformOneSecond is 1000. On Posix it's 1024.

Note that this means you should avoid assuming that you can get an accurate millisecond by taking mDNSPlatformOneSecond and dividing by 1000. Instead, figure out how many milliseconds you want, and divide to get that amount. For example, if you want 250 milliseconds, this is `mDNSPlatformOneSecond / 4`. If a tick were, for example, ten milliseconds, `mDNSPlatformOneSecond / 1000 * 250` would be zero, because / and * have the same precedence, so the expression is evaluated right-to-left. mDNSPlatformOneSecond would be 100, divided by 1000 is zero, times 250 is zero. Using the preferred method, 100 divided by 4 is 25. If you want the code to read more clearly, you could use parentheses to get the same effect: `mDNSPlatformOneSecond / (1000 / 250)`, but it might be better to just add a comment, as is done for example with `NATMAP_INIT_RETRY` in `mDNSCore/mDNSEmbeddedAPI.h`.
