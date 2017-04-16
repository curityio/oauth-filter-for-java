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

package se.curity.oauth;

import java.time.Clock;
import java.time.Instant;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A cache that expires it's entries after a given timeout
 * @param <K> The key
 * @param <V extends Expirable> A value that can expire
 */
public class ExpirationBasedCache<K, V extends Expirable>
{
    private final ConcurrentHashMap<K, V> _cache;
    private final Clock _clock;

    ExpirationBasedCache()
    {
        _cache = new ConcurrentHashMap<>();
        _clock = Clock.systemUTC();

        Timer timer = new Timer("cacheExpiration", true);
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                expireCacheEntries();
            }} , 60, 60);
    }

    public Optional<V> get(K key)
    {
        //optimistically get a value
        V value = _cache.get(key);

        //make sure it's not expired yet
        if (value != null && value.getExpiresAt().isAfter(Instant.now(_clock)))
        {
            value = null;
        }

        return Optional.ofNullable(value);
    }

    void put(K key, V value)
    {
        _cache.putIfAbsent(key, value);
    }

    private void expireCacheEntries()
    {
        Instant now = Instant.now(_clock);
        //This might miss the last entry if new are put in, but that's ok
        //it will be caught in the next expiration round instead.
        Set<K> keySet = new HashSet<>(_cache.keySet());

        for (K key : keySet)
        {
            V entry = _cache.get(key);

            if (now.isAfter(entry.getExpiresAt()))
            {
                _cache.remove(key);
            }
        }
    }

    void clear()
    {
        _cache.clear();
    }
}
