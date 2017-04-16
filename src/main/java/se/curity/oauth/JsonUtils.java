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

import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonReaderFactory;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.spi.JsonProvider;
import java.util.Collections;
import java.util.Optional;

final class JsonUtils
{
    private JsonUtils()
    {
    }

    static JsonReaderFactory createDefaultReaderFactory()
    {
        return JsonProvider.provider().createReaderFactory(Collections.emptyMap());
    }

    static String getString(JsonObject jsonObject, String name)
    {
        return Optional.ofNullable(jsonObject.get(name))
                .filter(it -> it.getValueType() == JsonValue.ValueType.STRING)
                .map(it -> ((JsonString) it).getString())
                .orElse(null);
    }

    static long getLong(JsonObject jsonObject, String name)
    {
        return Optional.ofNullable(jsonObject.get(name))
                .filter(it -> it.getValueType() == JsonValue.ValueType.NUMBER)
                .map(it -> ((JsonNumber) it).longValue())
                .orElse(Long.MIN_VALUE);
    }
}
