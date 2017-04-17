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

import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by tspencer on 17/04/17.
 */
public class AuthenticatedUserRequestWrapperTest
{
    @Test
    public void canAuthenticate() throws Exception
    {
        // GIVEN: an authenticated user
        AuthenticatedUser user = AuthenticatedUser.from(() -> "test-user");

        // AND: a request that wraps that authenticated user
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        AuthenticatedUserRequestWrapper authenticatedUserRequest = new AuthenticatedUserRequestWrapper(mockRequest, user);

        // WHEN: authenticate is called on the request
        boolean actual = authenticatedUserRequest.authenticate(null);

        // THEN: the result is true because the user is authenticated 
        assertTrue(actual);
    }

    /**
     * Test that authenticate returns true when the user isn't authenticate but the response is committed.
     *
     * <p>This behavior is defined in {@link HttpServletRequest#authenticate(HttpServletResponse)}:</p>
     *
     * <blockquote>
     *     Return false if authentication is incomplete and the underlying login mechanism has committed, in the
     *     response, the message (e.g., challenge) and HTTP status code to be returned to the user.
     * </blockquote>
     *
     * @see HttpServletRequest#authenticate(HttpServletResponse)
     */
    @Test
    public void authenticate() throws Exception
    {
        // GIVEN: a request that doesn't have a token that can be used to authenticate the user
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        AuthenticatedUserRequestWrapper authenticatedUserRequest = new AuthenticatedUserRequestWrapper(mockRequest, null);

        // AND: A request that is already committed and has the status code set to 401
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);
        when(mockResponse.getStatus()).thenReturn(HttpServletResponse.SC_UNAUTHORIZED);

        // WHEN: authenticate is called on the response
        boolean actual = authenticatedUserRequest.authenticate(mockResponse);

        // THEN: the result is true even though the user is yet authenticated
        assertTrue(actual);
    }
}