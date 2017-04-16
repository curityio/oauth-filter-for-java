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

import javax.json.JsonValue;
import java.util.logging.Logger;

enum JsonWebKeyType
{
    RSA,
    EC,
    OCT,
    UNSPECIFIED;

    private static final Logger _logger = Logger.getLogger(JsonWebKeyType.class.getName());

    static JsonWebKeyType from(JsonValue value)
    {
        if (value == null || value.toString().length() == 0)
        {
            return UNSPECIFIED;
        }

        if (value.getValueType() != JsonValue.ValueType.STRING)
        {
            _logger.warning(() -> String.format("Value '%s' is not a string, as required; it is %s",
                    value, value.getValueType()));
        }

        switch (value.toString())
        {
            case "RSA":
                return RSA;
            case "EC":
                return EC;
            case "oct":
                return OCT;
            default:

                _logger.warning(() -> String.format("Unknown enumeration value '%s' given.", value));

                throw new IllegalArgumentException("value");
        }
    }
}

