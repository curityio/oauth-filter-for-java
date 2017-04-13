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

@SuppressWarnings("unused") // Instantiated by GSON which sets these private fields based on a JSON object's values
public class OAuthIntrospectResponse
{
    private boolean active;
    private String sub;
    private String scope;
    private long exp;

    public boolean getActive()
    {
        return active;
    }

    public String getSub()
    {
        return sub;
    }

    public String getScope()
    {
        return scope;
    }

    public long getExp()
    {
        return exp;
    }
}
