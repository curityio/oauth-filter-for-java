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
import javax.json.JsonValue;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class JsonData implements Expirable
{
    private final JsonObject _jsonObject;
    private final Set<String> _scopes;

    JsonData(JsonObject jsonObject)
    {
        _jsonObject = jsonObject;
        _scopes = JsonUtils.getScopes(jsonObject);
    }

    JsonObject getJsonObject()
    {
        return _jsonObject;
    }

    public String getSubject()
    {
        return JsonUtils.getString(_jsonObject, "sub");
    }

    public Set<String> getScopes()
    {
        return _scopes;
    }

    public Set<String> getClaimNames()
    {
        return _jsonObject.keySet();
    }

    public JsonObject getClaims()
    {
        return _jsonObject;
    }

    public JsonValue getClaim(String claimName)
    {
        return _jsonObject.get(claimName);
    }

    @Override
    public Instant getExpiresAt()
    {
        return Instant.ofEpochSecond(JsonUtils.getLong(_jsonObject, "exp"));
    }
}
