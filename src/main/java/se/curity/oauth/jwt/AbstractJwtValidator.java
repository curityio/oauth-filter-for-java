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

package se.curity.oauth.jwt;

import com.google.common.base.Charsets;
import com.google.common.base.Preconditions;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.codec.binary.Base64;

import javax.annotation.Nullable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.google.common.base.Strings.isNullOrEmpty;

public class AbstractJwtValidator implements JwtValidator
{
    private final Gson _gson = new GsonBuilder()
            .disableHtmlEscaping()
            .create();

    @Nullable
    @Override
    public Map<String, Object> validate(String jwt) throws JwtValidationException
    {
        return null;
    }

    @Override
    public Optional<Map<String, Object>> validateAll(String jwt, String audience, String issuer) throws JwtValidationException
    {
        if (this.validate(jwt) == null)
        {
            return Optional.empty();
        }

        String[] jwtParts = jwt.split("\\.");

        if (jwtParts.length != 3)
        {
            throw new IllegalArgumentException("Incorrect JWT input");
        }

        String body = jwtParts[1];
        Base64 base64 = new Base64(true);

        @SuppressWarnings("unchecked")
        Map<String, Object> bodyMap = _gson.fromJson(new String(base64.decode(body), Charsets.UTF_8), Map.class);

        try
        {

            Double expD = (Double) bodyMap.get("exp");
            Double iatD = (Double) bodyMap.get("iat");

            long exp = Math.round(expD);
            long iat = Math.round(iatD);

            String aud = (String) bodyMap.get("aud");
            String iss = (String) bodyMap.get("iss");

            Preconditions.checkArgument(!isNullOrEmpty(aud), "aud claim is not present in JWT");
            Preconditions.checkArgument(!isNullOrEmpty(iss), "iss claim is not present in JWT");

            if (!aud.equals(audience))
            {
                return Optional.empty();
            }

            if (!iss.equals(issuer))
            {
                return Optional.empty();
            }

            Instant now = Instant.now();

            if (now.getEpochSecond() > exp)
            {
                return Optional.empty();
            }

            if (now.getEpochSecond() < iat)
            {
                return Optional.empty();
            }
        }
        catch (Exception e)
        {
            throw new JwtValidationException("Failed to extract data from Token");
        }

        Map<String, Object> result = new HashMap<>();

        for (String key : bodyMap.keySet())
        {
            // This can be a bit more elaborate filter...
            result.put(key, bodyMap.get(key));
        }

        return Optional.of(result);
    }

    /**
     * Convert base64 to bytes (ASCII)
     *
     * @param input input
     * @return The array of bytes
     */
    byte[] convertToBytes(String input)
    {
        byte[] bytes = new byte[input.length()];

        for (int i = 0; i < input.length(); i++)
        {
            //Convert and treat as ascii.
            int integer = (int) input.charAt(i);

            //Since byte is signed in Java we cannot use normal conversion
            //but must drop it into a byte array and trunkate.
            byte[] rawBytes = ByteBuffer.allocate(4).putInt(integer).array();
            //Only store the least significant byte (the others should be 0 TODO check)
            bytes[i] = rawBytes[3];
        }

        return bytes;
    }

    boolean validateSignature(byte[] signingInput, byte[] signature, PublicKey publicKey)
    {
        try
        {
            Signature verifier = Signature.getInstance("SHA256withRSA");

            verifier.initVerify(publicKey);
            verifier.update(signingInput);

            return verifier.verify(signature);
        }
        catch (Exception e)
        {
            throw new RuntimeException("Unable to validate JWT signature", e);
        }
    }

    PublicKey getKeyFromModAndExp(String modulus, String exponent) throws Exception
    {
        return RsaPublicKeyCreator.createPublicKey(modulus, exponent);
    }

    @Override
    public void close() throws IOException
    {

    }
}
