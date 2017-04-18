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

import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import java.io.Closeable;
import java.io.IOException;
import java.io.StringReader;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

final class JwkManager implements Closeable
{
    private static final Logger _logger = Logger.getLogger(JwkManager.class.getName());
    private static final String ACCEPT = "Accept";

    private final TimeBasedCache<String, JsonWebKey> _jsonWebKeyByKID;
    private final WebKeysClient _webKeysClient;
    private final ScheduledExecutorService _executor = Executors.newSingleThreadScheduledExecutor();
    private final JsonReaderFactory _jsonReaderFactory;

    JwkManager(long minKidReloadTimeInSeconds, WebKeysClient webKeysClient, JsonReaderFactory jsonReaderFactory)
    {
        _jsonWebKeyByKID = new TimeBasedCache<>(Duration.ofSeconds(minKidReloadTimeInSeconds), this::reload);
        _webKeysClient = webKeysClient;
        _jsonReaderFactory = jsonReaderFactory;

        // invalidate the cache periodically to avoid stale state
        _executor.scheduleAtFixedRate(this::ensureCacheIsFresh, 5, 15, TimeUnit.MINUTES);
    }

    /**
     * checks if the JsonWebKey exists in the local cached, otherwise this
     * method will call the JsonWebKeyService to get the new keys.
     *
     * @param keyId keyId
     * @return JsonWebKey
     */
    JsonWebKey getJsonWebKeyForKeyId(String keyId) throws JsonWebKeyNotFoundException
    {
        JsonWebKey key = _jsonWebKeyByKID.get(keyId);

        if (key != null)
        {
            return key;
        }

        throw new JsonWebKeyNotFoundException("Json Web Key does not exist: keyid=" + keyId);
    }

    private Map<String, JsonWebKey> reload()
    {
        Map<String, JsonWebKey> newKeys = new HashMap<>();

        try
        {
            JwksResponse response = parseJwksResponse(_webKeysClient.getKeys());

            for (JsonWebKey key : response.getKeys())
            {
                newKeys.put(key.getKeyId(), key);
            }

            _logger.info(() -> String.format("Fetched JsonWebKeys: %s", newKeys));

            return Collections.unmodifiableMap(newKeys);
        }
        catch (IOException e)
        {
            _logger.log(Level.SEVERE, "Could not contact JWKS Server", e);

            return Collections.emptyMap();
        }
    }

    private JwksResponse parseJwksResponse(String response)
    {
        JsonReader jsonReader = _jsonReaderFactory.createReader(new StringReader(response));
        JsonObject jsonObject = jsonReader.readObject();

        return new JwksResponse(jsonObject);
    }

    private void ensureCacheIsFresh()
    {
        _logger.info("Called ensureCacheIsFresh");

        Instant lastLoading = _jsonWebKeyByKID.getLastReloadInstant().orElse(Instant.MIN);
        boolean cacheIsNotFresh = lastLoading.isBefore(Instant.now()
                .minus(_jsonWebKeyByKID.getMinTimeBetweenReloads()));

        if (cacheIsNotFresh)
        {
            _logger.info("Invalidating JSON WebKeyID cache");

            _jsonWebKeyByKID.clear();
        }
    }

    @Override
    public void close() throws IOException
    {
        _executor.shutdown();

        if (_webKeysClient instanceof Closeable)
        {
            ((Closeable) _webKeysClient).close();
        }
    }
}
