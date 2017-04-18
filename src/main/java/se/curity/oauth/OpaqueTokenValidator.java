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
import java.time.Instant;
import java.util.Optional;

public class OpaqueTokenValidator implements Closeable, TokenValidator
{
    private final IntrospectionClient _introspectionClient;
    private final ExpirationBasedCache<String, OpaqueTokenData> _tokenCache;
    private final JsonReaderFactory _jsonReaderFactory;
    
    OpaqueTokenValidator(IntrospectionClient introspectionClient, JsonReaderFactory jsonReaderFactory)
    {
        _introspectionClient = introspectionClient;
        _tokenCache = new ExpirationBasedCache<>();
        _jsonReaderFactory = jsonReaderFactory;
    }

    public TokenData validate(String token) throws TokenValidationException
    {
        Optional<OpaqueTokenData> cachedValue = _tokenCache.get(token);

        if (cachedValue.isPresent())
        {
            return cachedValue.get();
        }

        String introspectJson;

        try
        {
            introspectJson = _introspectionClient.introspect(token);
        }
        catch (Exception e)
        {
            // TODO: Add logging
            throw new TokenValidationException("Failed to introspect token", e);
        }

        OAuthIntrospectResponse response = parseIntrospectResponse(introspectJson);

        if (response.getActive())
        {
            OpaqueTokenData newToken = new OpaqueTokenData(response.getSubject(), response.getExpiration(),
                    response.getScope());

            if (newToken.getExpiresAt().isAfter(Instant.now()))
            {
                //Note: If this cache is backed by some persistent storage, the token should be hashed and not stored
                //      in clear text
                _tokenCache.put(token, newToken);

                return newToken;
            }
            else
            {
                throw new ExpiredTokenException();
            }
        }
        else
        {
            throw new RevokedTokenException();
        }
    }

    private OAuthIntrospectResponse parseIntrospectResponse(String introspectJson)
    {
        JsonReader jsonReader = _jsonReaderFactory.createReader(new StringReader(introspectJson));
        JsonObject jsonObject = jsonReader.readObject();

        return new OAuthIntrospectResponse(jsonObject.getBoolean("active"), jsonObject.getString("sub"),
                jsonObject.getString("scope"), jsonObject.getInt("exp"));
    }

    @Override
    public void close() throws IOException
    {
        _introspectionClient.close();
        _tokenCache.clear();
    }
}
