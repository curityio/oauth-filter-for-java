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

package se.curity.oauth.opaque;

import java.time.Instant;

public class OpaqueToken implements Expirable
{
    private final Instant _expiresAt;
    private final String _scope;
    private final String _subject;

    OpaqueToken(String subject, long expiresAt, String scope)
    {
        _subject = subject;
        _scope = scope;
        _expiresAt = Instant.ofEpochSecond(expiresAt);
    }

    public String getScope()
    {
        return _scope;
    }

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
