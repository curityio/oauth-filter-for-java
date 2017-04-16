/*
 * Copyright (C) 2017 Curity AB.
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

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.Closeable;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import static org.apache.http.HttpHeaders.ACCEPT;

class DefaultIntrospectClient implements IntrospectionClient
{
    private static final Logger _logger = Logger.getLogger(DefaultIntrospectClient.class.getName());

    private final HttpClient _httpClient;
    private final URI _introspectionUri;
    private final String _clientId;
    private final String _clientSecret;

    DefaultIntrospectClient(URI introspectionUri, String clientId, String clientSecret, HttpClient httpClient)
    {
        _introspectionUri = introspectionUri;
        _clientId = clientId;
        _clientSecret = clientSecret;
        _httpClient = httpClient;
    }

    @Override
    public String introspect(String token) throws IOException
    {
        HttpPost post = new HttpPost(_introspectionUri);

        post.setHeader(ACCEPT, ContentType.APPLICATION_JSON.getMimeType());

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

        return EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
    }

    @Override
    public void close() throws IOException
    {
        if (_httpClient instanceof Closeable)
        {
            ((Closeable) _httpClient).close();
        }
    }
}
