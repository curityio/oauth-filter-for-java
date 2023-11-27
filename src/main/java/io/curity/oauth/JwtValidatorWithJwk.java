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

import javax.json.JsonReaderFactory;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

final class JwtValidatorWithJwk extends AbstractJwtValidator
{
    private static final Logger _logger = Logger.getLogger(JwtValidatorWithJwk.class.getName());

    private final JwkManager _jwkManager;

    JwtValidatorWithJwk(long minKidReloadTime, WebKeysClient webKeysClient, String audience, String issuer,
                        JsonReaderFactory jsonReaderFactory)
    {
        super(issuer, audience, jsonReaderFactory);
        
        _jwkManager = new JwkManager(minKidReloadTime, webKeysClient, jsonReaderFactory);
    }

    @Override
    protected Optional<PublicKey> getPublicKey(JwtHeader jwtHeader)
    {
        Optional<PublicKey> result = Optional.empty();

        try
        {
            JsonWebKey jsonWebKeyType = _jwkManager.getJsonWebKeyForKeyId(jwtHeader.getKeyId());

            switch (jsonWebKeyType.getKeyType()) {
                case RSA :
                    result = Optional.of(RsaPublicKeyCreator.createPublicKey(jsonWebKeyType.getModulus(),
                            jsonWebKeyType.getExponent()));
                    break;
                case OKP :
                    if (isEdDSAKey(jsonWebKeyType)) {
                        result = Optional.of(EdDSAPublicKeyCreator.createPublicKey(jsonWebKeyType.getEllipticalCurve(), jsonWebKeyType.getXCoordinate()));
                    } else {
                        throw new NoSuchAlgorithmException(String.format("Unsupported curve %s for key %s", jsonWebKeyType.getEllipticalCurve(), jsonWebKeyType.getKeyId()));
                    }
                    break;
                case EC :
                case OCT :
                default:
                    throw new NoSuchAlgorithmException(String.format("Unsupported key type %s for key %s", jsonWebKeyType.getKeyType(), jsonWebKeyType.getKeyId()));
            }
        }
        catch (JsonWebKeyNotFoundException e)
        {
            // this is not a very exceptional occurrence, so let's not log a stack-trace
            _logger.info(() -> String.format("Could not find requested JsonWebKey: %s", e));
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            _logger.log(Level.WARNING, "Could not create public key", e);
        }

        return result;
    }

    private boolean isEdDSAKey(JsonWebKey jsonWebKey) {
        String curve = jsonWebKey.getEllipticalCurve();
        return curve != null && (curve.equals("Ed25519") || curve.equals("Ed448"));
    }

    @Override
    public void close() throws IOException
    {
        _jwkManager.close();
    }
}
