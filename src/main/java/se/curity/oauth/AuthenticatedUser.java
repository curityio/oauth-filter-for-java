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
import javax.json.JsonString;
import javax.json.JsonValue;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;

public class AuthenticatedUser
{
    private static final BiFunction<JsonObject, String, String> _toStringFn = (jsonObject, name) -> Optional
            .ofNullable(jsonObject.get(name))
            .filter(it -> it.getValueType() == JsonValue.ValueType.STRING)
            .map(it -> ((JsonString) it).getString())
            .orElse(null);

    private final String _sub;
    private final String _scope;

    AuthenticatedUser(String subject, String scope)
    {
        _sub = subject;
        _scope = scope;
    }

    public String getSubject()
    {
        return _sub;
    }

    public Optional<String> getScope()
    {
        return Optional.ofNullable(_scope);
    }

    static AuthenticatedUser from(JsonObject tokenData)
    {
        Objects.requireNonNull(tokenData);
        Objects.requireNonNull(tokenData.get("sub"));

        String sub = _toStringFn.apply(tokenData, "sub");
        String scope = _toStringFn.apply(tokenData, "scope");

        return new AuthenticatedUser(sub, scope);
    }
}
