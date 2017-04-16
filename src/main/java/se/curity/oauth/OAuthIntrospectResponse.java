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

class OAuthIntrospectResponse
{
    private final boolean _active;
    private final String _subject;
    private final String _scope;
    private final long _expiration;

    OAuthIntrospectResponse(boolean active, String subject, String scope, long expiration)
    {
        _active = active;
        _subject = subject;
        _scope = scope;
        _expiration = expiration;
    }

    boolean getActive()
    {
        return _active;
    }

    String getSubject()
    {
        return _subject;
    }

    String getScope()
    {
        return _scope;
    }

    long getExpiration()
    {
        return _expiration;
    }
}
