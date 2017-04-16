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

import javax.servlet.FilterConfig;
import javax.servlet.UnavailableException;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

final class FilterHelper
{
    private FilterHelper()
    {
        // no instantiation - static functions only
    }

    static Map<String, String> initParamsMapFrom(FilterConfig config)
    {
        Map<String, String> result = new LinkedHashMap<>();
        Enumeration<String> names = config.getInitParameterNames();

        while (names.hasMoreElements())
        {
            String name = names.nextElement();

            result.put(name, config.getInitParameter(name));
        }

        return result;
    }

    static String getInitParamValue(String name, Map<String, ?> initParams) throws UnavailableException
    {
        Optional<String> value = getSingleValue(name, initParams);

        if (value.isPresent())
        {
            return value.get();
        }
        else
        {
            throw new UnavailableException(missingInitParamMessage(name));
        }
    }

    static <T> T getInitParamValue(String name, Map<String, ?> initParams,
                                   Function<String, T> converter) throws UnavailableException
    {
        return converter.apply(getInitParamValue(name, initParams));
    }

    static <T> Optional<T> getOptionalInitParamValue(String name, Map<String, ?> initParams,
                                                     Function<String, T> converter) throws UnavailableException
    {
        Optional<String> value = getSingleValue(name, initParams);

        return value.flatMap(s -> Optional.ofNullable(converter.apply(s)));
    }

    private static Optional<String> getSingleValue(String name, Map<String, ?> initParams) throws
            UnavailableException
    {
        return Optional.ofNullable(initParams.get(name)).map(Object::toString);
    }

    private static String missingInitParamMessage(String paramName)
    {
        return String.format("%s - missing required initParam [%s]",
                OAuthFilter.class.getName(),
                paramName);
    }
}
