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
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class OpaqueTokenValidator implements Closeable
{
    private static final Logger _logger = LoggerFactory.getLogger(OpaqueTokenValidator.class);

    private final Gson _gson = new GsonBuilder()
            .disableHtmlEscaping()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .create();

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

    @Nullable
    public OpaqueToken validate(String token) throws IOException
    {
        @Nullable OpaqueToken cachedValue = _tokenCache.get(token);

        if (cachedValue != null)
        {
            return cachedValue;
        }

        String introspectJson = introspect(token);
        OAuthIntrospectResponse response = parseIntrospectResponse(introspectJson);

        if (response.getActive())
        {
            OpaqueToken newToken = new OpaqueToken(response.getSub(), response.getExp(),response.getScope());

            if (newToken.getExpiresAt().isAfter(Instant.now()))
            {
                //Note: If this cache is backed by some persistent storage, the token should be hashed and not stored
                //      in clear text
                _tokenCache.put(token, newToken);

                return newToken;
            }
        }

        return null;
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
            _logger.error("Got error from introspection server: " + response.getStatusLine().getStatusCode());

            throw new IOException("Got error from introspection server: " + response.getStatusLine().getStatusCode());
        }

        return EntityUtils.toString(response.getEntity(), Charsets.UTF_8);
    }

    protected OAuthIntrospectResponse parseIntrospectResponse(String introspectJson)
    {
        return _gson.fromJson(introspectJson, OAuthIntrospectResponse.class);
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
