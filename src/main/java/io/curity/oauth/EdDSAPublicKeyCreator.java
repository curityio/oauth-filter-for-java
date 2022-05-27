package io.curity.oauth;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

public class EdDSAPublicKeyCreator {

    static PublicKey createPublicKey(String curveName, String publicKeyJwt) throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        byte[] publicKeyBytes = decoder.decode(publicKeyJwt);
        int b = publicKeyBytes.length;

        if (b != 32 && b != 57) {
            throw new InvalidKeySpecException("Invalid key length for EdDSA key.");
        }

        // Byte array is in little endian encoding, the most significant bit in final octet indicates if X is negative or not:
        // https://www.rfc-editor.org/rfc/rfc8032.html#section-3.1
        // https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.2
        // https://www.rfc-editor.org/rfc/rfc8032.html#section-3.1
        boolean XIsNegative = (publicKeyBytes[b-1] & 0x80) != 0;
        // Recover y value by clearing x-bit.
        publicKeyBytes[b-1] = (byte)(publicKeyBytes[b-1] & 0x7f);

        byte[] publicKeyBytesBE = new byte[b];

        // Switch to big endian encoding
        for(int i = 0; i < b; i++) {
            publicKeyBytesBE[i] = publicKeyBytes[b-1-i];
        }

        // Create key from specs
        NamedParameterSpec crvKeySpec = new NamedParameterSpec(curveName);
        EdECPublicKeySpec edECPublicKeySpec = new EdECPublicKeySpec(crvKeySpec, new EdECPoint(XIsNegative, new BigInteger(1, publicKeyBytesBE)));
        KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");

        return keyFactory.generatePublic(edECPublicKeySpec);
    }

}
