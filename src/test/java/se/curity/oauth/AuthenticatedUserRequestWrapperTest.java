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
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collection;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthenticatedUserRequestWrapperTest
{
    @Test
    public void testCanAuthenticate() throws Exception
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

    @RunWith(value = Parameterized.class)
    public static class AuthenticatedWhenUserIsNullTest
    {
        private final int _statusCode;
        private final boolean _expectedResult;
        private final boolean _isCommitted;

        public AuthenticatedWhenUserIsNullTest(int statusCode, boolean isCommitted, boolean expectedResult)
        {
            _statusCode = statusCode;
            _isCommitted = isCommitted;
            _expectedResult = expectedResult;
        }

        @Parameterized.Parameters(
                name = "{index}: testAuthenticateWhenResponseIsCommitted: status={0}, isCommitted={1}, authenticated={2}")
        public static Collection<Object[]> data()
        {
            return Arrays.asList(new Object[][] {
                    {HttpServletResponse.SC_UNAUTHORIZED, true, true},
                    {HttpServletResponse.SC_UNAUTHORIZED, false, false},
                    {HttpServletResponse.SC_FORBIDDEN, true, true},
                    {HttpServletResponse.SC_FORBIDDEN, false, false},
                    {HttpServletResponse.SC_SEE_OTHER, true, false},
                    {HttpServletResponse.SC_OK, false, false},
            });
        }

        /**
         * Test that authenticate returns the correct value when the user isn't authenticate but the response is committed.
         *
         * <p>When an authentication challenge has been sent (i.e., a 401 or 403), then the user is considered
         * authenticated (or more precisely, being authenticated). If the status code is some other value though, the
         * user isn't be authenticated, so the response should be false.</p>
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
        public void testAuthenticateWhenResponseIsCommitted() throws Exception
        {
            // GIVEN: a request that doesn't have a token that can be used to authenticate the user
            HttpServletRequest mockRequest = mock(HttpServletRequest.class);
            AuthenticatedUserRequestWrapper authenticatedUserRequest = new AuthenticatedUserRequestWrapper(mockRequest, null);

            // AND: A request that is already committed and has the status code set to 401
            HttpServletResponse mockResponse = mock(HttpServletResponse.class);
            when(mockResponse.isCommitted()).thenReturn(_isCommitted);
            when(mockResponse.getStatus()).thenReturn(_statusCode);

            // WHEN: authenticate is called on the response
            boolean actual = authenticatedUserRequest.authenticate(mockResponse);

            // THEN: the result is true even though the user is yet authenticated
            assertThat(actual, is(_expectedResult));
        }
    }
}