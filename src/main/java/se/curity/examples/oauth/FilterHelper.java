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

package se.curity.examples.oauth;

import com.google.common.collect.*;

import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.function.Function;

import static com.google.common.base.MoreObjects.firstNonNull;
import static com.google.common.base.Preconditions.checkArgument;

// intentionally package-private
final class FilterHelper
{
    private FilterHelper()
    {
        // no instantiation - static functions only
    }

    static ImmutableMultimap<String, String> initParamsMapFrom(FilterConfig config)
    {
        Multimap<String, String> result = Multimaps.newListMultimap(
                new LinkedHashMap<>(),
                ArrayList::new);

        Enumeration<?> names = config.getInitParameterNames();

        while (names.hasMoreElements())
        {
            String name = names.nextElement().toString();

            if (config.getInitParameter(name) != null)
            {
                result.put(name, config.getInitParameter(name));
            }
        }

        return ImmutableMultimap.copyOf(result);
    }

    static String getInitParamValue(String name, Multimap<String, String> initParams)
    {
        Optional<String> value = getSingleValue(name, initParams);

        if (value.isPresent())
        {
            return value.get();
        }
        else
        {
            throw new IllegalStateException(missingInitParamMessage(name));
        }
    }

    static <T> T getInitParamValue(String name, Multimap<String, String> initParams,
                                   Function<String, T> converter)
    {
        return converter.apply(getInitParamValue(name, initParams));
    }

    static <T> Optional<T> getOptionalInitParamValue(String name, Multimap<String, String> initParams,
                                                     Function<String, T> converter)
    {
        Optional<String> value = getSingleValue(name, initParams);

        return value.flatMap(s -> Optional.ofNullable(converter.apply(s)));
    }

    private static Optional<String> getSingleValue(String name, Multimap<String, String> initParams)
    {
        Collection<String> values = initParams.get(name);

        if (values.size() > 1)
        {
            throw new IllegalStateException(String.format("More than one value for parameter [%s]", name));
        }

        return Optional.ofNullable(Iterables.getFirst(values, null));
    }

    private static String missingInitParamMessage(String paramName)
    {
        return String.format("%s - missing required initParam [%s]",
                OAuthFilter.class.getName(),
                paramName);
    }
}
