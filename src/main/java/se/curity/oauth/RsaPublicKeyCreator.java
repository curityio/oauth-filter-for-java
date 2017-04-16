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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

class RsaPublicKeyCreator
{
    static PublicKey createPublicKey(String modulus, String exponent) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        Base64.Decoder decoder = Base64.getDecoder();
        BigInteger bigModulus = new BigInteger(1, decoder.decode(modulus));
        BigInteger bigExponent = new BigInteger(1, decoder.decode(exponent));
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(bigModulus, bigExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(publicKeySpec);
    }
}
