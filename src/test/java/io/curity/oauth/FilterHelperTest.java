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

import jakarta.servlet.FilterConfig;
import jakarta.servlet.UnavailableException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

public class FilterHelperTest
{
    @Mock
    private FilterConfig mockFilterConfig;

    @Before
    public void setUp()
    {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void canProvideSimpleStrings() throws UnavailableException
    {
        Map<String, Object> params = Collections.singletonMap("tokenEndpoint", "https://example.com/token");

        String result = FilterHelper.getInitParamValue("tokenEndpoint", params);

        assertEquals("https://example.com/token", result);
    }

    @Test
    public void canProvideSimpleStringsWithConverter() throws UnavailableException
    {
        Map<String, Object> params = Collections.singletonMap("maxRetries", "5");

        Integer result = FilterHelper.getInitParamValue("maxRetries", params, Integer::parseInt);

        assertEquals(Integer.valueOf(5), result);
    }

    @Test
    public void canProvideWhiteSeparatedStringLists() throws UnavailableException
    {
        Map<String, Object> params = Collections.singletonMap("scope", "read write delete");

        List<String> result = FilterHelper.getWhitespaceSeparatedInitParamValues("scope", params);

        assertNotNull(result);
        assertEquals(3, result.size());
        assertEquals("read", result.get(0));
        assertEquals("write", result.get(1));
        assertEquals("delete", result.get(2));
    }

    @Test
    public void canProvideWhiteSeparatedStringListsWithVariousWhitespace() throws UnavailableException
    {
        Map<String, Object> params = Collections.singletonMap("scope", "read  write\tdelete\nupdate");

        List<String> result = FilterHelper.getWhitespaceSeparatedInitParamValues("scope", params);

        assertNotNull(result);
        assertEquals(4, result.size());
        assertEquals("read", result.get(0));
        assertEquals("write", result.get(1));
        assertEquals("delete", result.get(2));
        assertEquals("update", result.get(3));
    }

    @Test
    public void canProvideSingleValueInWhiteSeparatedStringList() throws UnavailableException
    {
        Map<String, Object> params = Collections.singletonMap("scope", "read");

        List<String> result = FilterHelper.getWhitespaceSeparatedInitParamValues("scope", params);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("read", result.get(0));
    }

    @Test(expected = UnavailableException.class)
    public void failsWhenParameterIsMissing() throws UnavailableException
    {
        Map<String, Object> params = Collections.emptyMap();

        FilterHelper.getInitParamValue("tokenEndpoint", params);
    }

    @Test
    public void failsWhenParameterIsMissingWithCorrectMessage() throws UnavailableException
    {
        Map<String, Object> params = Collections.emptyMap();

        try
        {
            FilterHelper.getInitParamValue("tokenEndpoint", params);
            fail("Should have thrown UnavailableException");
        }
        catch (UnavailableException e)
        {
            assertTrue(e.getMessage().contains("missing required initParam [tokenEndpoint]"));
            assertTrue(e.getMessage().contains("OAuthFilter"));
        }
    }

    @Test
    public void doesNotFailWhenOptionalParameterIsMissing() throws UnavailableException
    {
        Map<String, Object> params = Collections.emptyMap();

        Optional<String> result = FilterHelper.getOptionalInitParamValue("audience", params,
                v -> v);

        assertFalse(result.isPresent());
    }

    @Test
    public void doesNotFailWhenOptionalParameterIsPresentWithConverter() throws UnavailableException
    {
        Map<String, Object> params = Collections.singletonMap("connectionTimeout", "30000");

        Optional<Long> result = FilterHelper.getOptionalInitParamValue("connectionTimeout", params,
                Long::parseLong);

        assertTrue(result.isPresent());
        assertEquals(Long.valueOf(30000), result.get());
    }

    @Test
    public void doesNotFailWhenOptionalParameterIsNull() throws UnavailableException
    {
        Map<String, Object> params = Collections.singletonMap("someParam", null);

        Optional<String> result = FilterHelper.getOptionalInitParamValue("someParam", params,
                v -> v);

        assertFalse(result.isPresent());
    }

    @Test
    public void doesNotFailWhenNoParametersProvidedForWhiteSpaceSeparatedStringLists()
            throws UnavailableException
    {
        Map<String, Object> params = Collections.emptyMap();

        List<String> result = FilterHelper.getWhitespaceSeparatedInitParamValues("scope", params);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    public void initParamsMapFromWithNoParameters()
    {
        when(mockFilterConfig.getInitParameterNames())
                .thenReturn(Collections.emptyEnumeration());

        Map<String, String> result = FilterHelper.initParamsMapFrom(mockFilterConfig);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    public void initParamsMapFromWithSingleParameter()
    {
        when(mockFilterConfig.getInitParameterNames())
                .thenReturn(Collections.enumeration(Collections.singletonList("tokenEndpoint")));
        when(mockFilterConfig.getInitParameter("tokenEndpoint"))
                .thenReturn("https://example.com/token");

        Map<String, String> result = FilterHelper.initParamsMapFrom(mockFilterConfig);

        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals("https://example.com/token", result.get("tokenEndpoint"));
    }

    @Test
    public void initParamsMapFromWithMultipleParameters()
    {
        List<String> paramNames = Arrays.asList("tokenEndpoint", "scope", "audience");
        when(mockFilterConfig.getInitParameterNames())
                .thenReturn(Collections.enumeration(paramNames));
        when(mockFilterConfig.getInitParameter("tokenEndpoint"))
                .thenReturn("https://example.com/token");
        when(mockFilterConfig.getInitParameter("scope"))
                .thenReturn("read write");
        when(mockFilterConfig.getInitParameter("audience"))
                .thenReturn("api");

        Map<String, String> result = FilterHelper.initParamsMapFrom(mockFilterConfig);

        assertNotNull(result);
        assertEquals(3, result.size());
        assertEquals("https://example.com/token", result.get("tokenEndpoint"));
        assertEquals("read write", result.get("scope"));
        assertEquals("api", result.get("audience"));
    }
}
