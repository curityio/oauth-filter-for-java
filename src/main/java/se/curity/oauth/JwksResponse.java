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

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonValue;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class JwksResponse
{
    private final List<JsonWebKey> _keys;

    JwksResponse(JsonObject jsonObject)
    {
        JsonValue keys = jsonObject.get("keys");

        if (keys.getValueType() != JsonValue.ValueType.ARRAY)
        {
            _keys = Collections.emptyList();
        }
        else
        {
            _keys = Stream.of((JsonArray)keys)
                    .filter(it -> it.getValueType() == JsonValue.ValueType.OBJECT)
                    .map(it -> (JsonObject) it)
                    .map(JsonWebKey::new)
                    .collect(Collectors.toList());
        }
    }

    List<JsonWebKey> getKeys()
    {
        return _keys;
    }
}
