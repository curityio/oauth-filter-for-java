/*
 * Copyright (C) 2016 Curity AB.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.curity.examples.oauth.jwt;

import com.google.common.collect.ImmutableMap;
import org.junit.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TimeBasedCacheTest
{

    @Test
    public void doesNotReloadCacheWithinTimeLimit()
            throws Exception
    {
        // fake clock returns current time, then the same thing again,
        // then 4 seconds later, then 8 seconds later.
        Clock fakeClock = mock(Clock.class);
        Instant now = Instant.now();
        when(fakeClock.millis()).thenCallRealMethod();
        when(fakeClock.instant()).thenReturn(
                now, // get("0") - first map loading
                now, // cache asks when the latest loading happened
                now.plus(Duration.ofSeconds(4)), // get("1") - no reloading
                // get("0") - should not even ask about the time as entry was found
                now.plus(Duration.ofSeconds(4)), // get("1") - no reloading
                now.plus(Duration.ofSeconds(8))); // get("1") - reload

        @SuppressWarnings("unchecked")
        Supplier<ImmutableMap> fakeSupplier = mock(Supplier.class);
        when(fakeSupplier.get()).thenReturn(
                ImmutableMap.of("0", 0),
                ImmutableMap.of("1", 1));

        // the map will always contain a single entry with the number of reloads as in
        // ("reloads" -> reloads)
        AtomicInteger reloads = new AtomicInteger(0);

        TimeBasedCache<String, Integer> cache = new TimeBasedCache<>(Duration.ofSeconds(5),
                () -> ImmutableMap.copyOf(ImmutableMap.of(Integer.toString(reloads.get()),
                        reloads.getAndIncrement())),
                ImmutableMap.of(), fakeClock);

        // should have only ("0" -> 0) in the map in the beginning
        assertNotNull(cache.get("0"));
        assertNull(cache.get("1"));

        // second time we try, the map should not reload
        assertNotNull(cache.get("0"));
        assertNull(cache.get("1"));

        // when the first reload happens, the cache contains ("1" -> 1)
        assertNotNull(cache.get("1"));
        assertNull(cache.get("0"));
    }

}
