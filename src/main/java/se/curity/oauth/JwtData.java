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

import javax.json.JsonObject;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class JwtData implements TokenData, Expirable
{
    private static final String[] NO_SCOPES = {};

    private final JsonObject _jsonObject;
    private final Set<String> _scopes;

    JwtData(JsonObject jsonObject)
    {
        _jsonObject = jsonObject;

        String scopesInToken = JsonUtils.getString(_jsonObject, "scope");
        String[] presentedScopes = scopesInToken == null ? NO_SCOPES : scopesInToken.split("\\s+");
        
        _scopes = new HashSet<>(Arrays.asList(presentedScopes));
    }

    JsonObject getJsonObject()
    {
        return _jsonObject;
    }

    @Override
    public String getSubject()
    {
        return JsonUtils.getString(_jsonObject, "sub");
    }

    @Override
    public Set<String> getScopes()
    {
        return _scopes;
    }

    @Override
    public Instant getExpiresAt()
    {
        return Instant.ofEpochSecond(JsonUtils.getLong(_jsonObject, "exp"));
    }
}
