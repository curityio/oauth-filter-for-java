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
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

import static org.apache.http.HttpHeaders.ACCEPT;

class DefaultWebKeysClient implements WebKeysClient
{
    private static final Logger _logger = Logger.getLogger(DefaultWebKeysClient.class.getName());
    private final URI _jwksUri;
    private final HttpClient _httpClient;

    DefaultWebKeysClient(URI jwksUri, HttpClient httpClient)
    {
        _jwksUri = jwksUri;
        _httpClient = httpClient;
    }

    @Override
    public String getKeys() throws IOException
    {
        HttpGet get = new HttpGet(_jwksUri);

        get.setHeader(ACCEPT, ContentType.APPLICATION_JSON.getMimeType());

        HttpResponse response = _httpClient.execute(get);

        if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK)
        {
            _logger.severe(() -> "Got error from Jwks server: " + response.getStatusLine().getStatusCode());

            throw new IOException("Got error from Jwks server: " + response.getStatusLine().getStatusCode());
        }

        return EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
    }
}
