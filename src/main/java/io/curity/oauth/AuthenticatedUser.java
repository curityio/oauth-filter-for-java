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

package io.curity.oauth;

import javax.json.JsonObject;
import javax.json.JsonValue;
import java.util.Objects;
import java.util.Set;

public class AuthenticatedUser
{
    private final String _sub;
    private final Set<String> _scopes;
    private final JsonData _jsonData;

    private AuthenticatedUser(String subject, Set<String> scopes, JsonData jsonData)
    {
        _sub = subject;
        _scopes = scopes;
        _jsonData = jsonData;
    }

    public String getSubject()
    {
        return _sub;
    }

    public Set<String> getScopes()
    {
        return _scopes;
    }

    public JsonValue getClaim(String name)
    {
        return _jsonData.getClaim(name);
    }

    public JsonObject getClaims()
    {
        return _jsonData.getClaims();
    }

    static AuthenticatedUser from(JsonData tokenData)
    {
        Objects.requireNonNull(tokenData);

        String subject = tokenData.getSubject();

        Objects.requireNonNull(subject);

        return new AuthenticatedUser(subject, tokenData.getScopes(), tokenData);
    }
}
