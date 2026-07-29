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

package io.curity.oauth;

import javax.json.JsonArray;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonReaderFactory;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.spi.JsonProvider;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

final class JsonUtils
{
    private static final String[] NO_SCOPES = {};

    private JsonUtils()
    {
    }

    static JsonReaderFactory createDefaultReaderFactory()
    {
        return JsonProvider.provider().createReaderFactory(Collections.emptyMap());
    }

    static Set<String> getScopes(JsonObject jsonObject)
    {
        String scopesInToken = getString(jsonObject, "scope");
        String[] presentedScopes = scopesInToken == null ? NO_SCOPES : scopesInToken.split("\\s+");

        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(presentedScopes)));
    }

    static String getString(JsonObject jsonObject, String name)
    {
        return Optional.ofNullable(jsonObject.get(name))
                .filter(it -> it.getValueType() == JsonValue.ValueType.STRING)
                .map(it -> stringValue((JsonString) it))
                .orElse(null);
    }

    static Set<String> getStringOrStrings(JsonObject jsonObject, String name)
    {
        return Optional.ofNullable(jsonObject.get(name))
                .filter(it -> it.getValueType() == JsonValue.ValueType.STRING || it.getValueType() == JsonValue.ValueType.ARRAY)
                .map(JsonUtils::stringOrStringArrayValue)
                .orElse(Collections.emptySet());
    }

    static long getLong(JsonObject jsonObject, String name)
    {
        return Optional.ofNullable(jsonObject.get(name))
                .filter(it -> it.getValueType() == JsonValue.ValueType.NUMBER)
                .map(it -> ((JsonNumber) it).longValue())
                .orElse(Long.MIN_VALUE);
    }

    private static String stringValue(JsonValue value)
    {
        return ((JsonString) value).getString();
    }

    private static Set<String> stringOrStringArrayValue(JsonValue value)
    {
        if (value.getValueType() == JsonValue.ValueType.STRING)
        {
            return Set.of(stringValue(value));
        }
        if (value.getValueType() == JsonValue.ValueType.ARRAY)
        {
            return ((JsonArray) value).stream()
                    .map(JsonUtils::stringValue)
                    .collect(Collectors.toSet());
        }

        // be extremely lenient and ignore the value
        return Set.of();
    }
}
