package io.curity.oauth;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;

public class EdDSAPublicKeyCreator {

    static PublicKey createPublicKey(String curveName, String publicKeyJwt) throws InvalidKeySpecException, NoSuchAlgorithmException
    {

        Base64.Decoder decoder = Base64.getUrlDecoder();
        BigInteger publicKeyEdDSA = new BigInteger(1, decoder.decode(publicKeyJwt));

        NamedParameterSpec curveSpec = new NamedParameterSpec(curveName); // Get parameters for the given elliptic curve
        // Get parameters for the signature algorithm. As by RFC8932, pre-hashing should not be used: https://www.rfc-editor.org/rfc/rfc8032.html#section-8.5
        EdECPublicKeySpec edDSAPublicKeySpec = new EdECPublicKeySpec(curveSpec, new EdECPoint(false, publicKeyEdDSA));

        KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
        return keyFactory.generatePublic(edDSAPublicKeySpec);
    }
}
