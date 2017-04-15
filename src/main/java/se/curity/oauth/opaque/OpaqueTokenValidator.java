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

package se.curity.oauth.opaque;

import com.google.common.base.Charsets;
import com.google.common.net.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;

public class OpaqueTokenValidator implements Closeable
{
    private static final Logger _logger = Logger.getLogger(OpaqueTokenValidator.class.getName());

    private final URI _introspectionUri;
    private final String _clientId;
    private final String _clientSecret;
    private final HttpClient _httpClient;

    private final ExpirationBasedCache<String, OpaqueToken> _tokenCache;

    public OpaqueTokenValidator(URI introspectionUri, String clientId, String clientSecret, HttpClient httpClient)
    {
        _introspectionUri = introspectionUri;
        _clientId = clientId;
        _clientSecret = clientSecret;
        _httpClient = httpClient;
        _tokenCache = new ExpirationBasedCache<>();
    }

    public Optional<OpaqueToken> validate(String token) throws IOException
    {
        Optional<OpaqueToken> cachedValue = _tokenCache.get(token);

        if (cachedValue != null)
        {
            return cachedValue;
        }

        String introspectJson = introspect(token);
        OAuthIntrospectResponse response = parseIntrospectResponse(introspectJson);

        if (response.getActive())
        {
            OpaqueToken newToken = new OpaqueToken(response.getSubject(), response.getExpiration(),response.getScope());

            if (newToken.getExpiresAt().isAfter(Instant.now()))
            {
                //Note: If this cache is backed by some persistent storage, the token should be hashed and not stored
                //      in clear text
                _tokenCache.put(token, newToken);

                return Optional.of(newToken);
            }
        }

        return Optional.empty();
    }

    protected String introspect(String token) throws IOException
    {
        HttpPost post = new HttpPost(_introspectionUri);

        post.setHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());

        List<NameValuePair> params = new ArrayList<>(3);

        params.add(new BasicNameValuePair("token", token));
        params.add(new BasicNameValuePair("client_id", _clientId));
        params.add(new BasicNameValuePair("client_secret", _clientSecret));

        post.setEntity(new UrlEncodedFormEntity(params));

        HttpResponse response = _httpClient.execute(post);

        if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK)
        {
            _logger.severe(() -> "Got error from introspection server: " + response.getStatusLine().getStatusCode());

            throw new IOException("Got error from introspection server: " + response.getStatusLine().getStatusCode());
        }

        return EntityUtils.toString(response.getEntity(), Charsets.UTF_8);
    }

    private OAuthIntrospectResponse parseIntrospectResponse(String introspectJson)
    {
        JsonReader jsonReader = Json.createReader(new StringReader(introspectJson));
        JsonObject jsonObject = jsonReader.readObject();

        return new OAuthIntrospectResponse(jsonObject.getBoolean("active"), jsonObject.getString("sub"),
                jsonObject.getString("scope"), jsonObject.getInt("exp"));
    }

    @Override
    public void close() throws IOException
    {
        if (_httpClient instanceof Closeable)
        {
            ((Closeable) _httpClient).close();
        }

        _tokenCache.clear();
    }
}
