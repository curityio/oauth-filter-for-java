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

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

class OpaqueTokenData implements TokenData, Expirable
{
    private static final String[] NO_SCOPES = {};

    private final Instant _expiresAt;
    private final Set<String> _scopes;
    private final String _subject;

    OpaqueTokenData(String subject, long expiresAt, String scope)
    {
        _subject = subject;
        _expiresAt = Instant.ofEpochSecond(expiresAt);

        String[] presentedScopes = scope == null ? NO_SCOPES : scope.split("\\s+");

        _scopes = new HashSet<>(Arrays.asList(presentedScopes));
    }

    @Override
    public Set<String> getScopes()
    {
        return _scopes;
    }

    @Override
    public String getSubject()
    {
        return _subject;
    }

    @Override
    public Instant getExpiresAt()
    {
        return _expiresAt;
    }
}
