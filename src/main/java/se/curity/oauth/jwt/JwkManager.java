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

package se.curity.oauth.jwt;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableMap;
import com.google.common.net.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
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

    private final URI _jwksUri;
    private final TimeBasedCache<String, JsonWebKey> _jsonWebKeyByKID;
    private final HttpClient _httpClient;
    private final ScheduledExecutorService _executor = Executors.newSingleThreadScheduledExecutor();

    JwkManager(URI jwksUri, long minKidReloadTimeInSeconds, HttpClient httpClient)
    {
        _jwksUri = jwksUri;
        _jsonWebKeyByKID = new TimeBasedCache<>(
                Duration.ofSeconds(minKidReloadTimeInSeconds), this::reload);
        _httpClient = httpClient;

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

    private ImmutableMap<String, JsonWebKey> reload()
    {
        Map<String, JsonWebKey> newKeys = new HashMap<>();

        try
        {
            JwksResponse response = parseJwksResponse(fetchKeys());

            for (JsonWebKey key : response.getKeys())
            {
                newKeys.put(key.getKeyId(), key);
            }

            _logger.info(() -> String.format("Fetched JsonWebKeys: %s", newKeys));

            return ImmutableMap.copyOf(newKeys);
        }
        catch (IOException e)
        {
            _logger.log(Level.SEVERE, "Could not contact Jwks Server at " + _jwksUri, e);

            return ImmutableMap.of();
        }
    }

    private String fetchKeys() throws IOException
    {
        HttpGet get = new HttpGet(_jwksUri);

        get.setHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());

        HttpResponse response = _httpClient.execute(get);

        if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK)
        {
            _logger.severe(() -> "Got error from Jwks server: " + response.getStatusLine().getStatusCode());

            throw new IOException("Got error from Jwks server: " + response.getStatusLine().getStatusCode());
        }

        return EntityUtils.toString(response.getEntity(), Charsets.UTF_8);
    }

    private JwksResponse parseJwksResponse(String response)
    {
        JsonReader jsonReader = Json.createReader(new StringReader(response));
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

        if (_httpClient instanceof Closeable)
        {
            ((Closeable) _httpClient).close();
        }
    }
}
