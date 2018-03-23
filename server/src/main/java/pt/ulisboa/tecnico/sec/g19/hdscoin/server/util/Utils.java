package pt.ulisboa.tecnico.sec.g19.hdscoin.server.util;

import pt.ulisboa.tecnico.sec.g19.hdscoin.server.Serialization;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Utils {

    private static final int NONCE_SIZE = 20;
    private static final String AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static SecureRandom rnd = new SecureRandom();
    public static String randomNonce( ){
        StringBuilder sb = new StringBuilder( NONCE_SIZE );
        for( int i = 0; i < NONCE_SIZE; i++ )
            sb.append( AB.charAt( rnd.nextInt(AB.length()) ) );
        return sb.toString();
    }

    //Returns a signature in base64 over an hash input
    public static String generateSignature(String hashInput, ECPrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String hash = Arrays.toString(digest.digest(hashInput.getBytes(StandardCharsets.UTF_8)));

        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(hash.getBytes("UTF-8"));
        return new String(Base64.getEncoder().encode(ecdsaSign.sign()), StandardCharsets.UTF_8);
    }

    public static boolean checkSignature(String signature, String hashInput, String publicKey) throws SignatureException, KeyException, NoSuchProviderException, NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String hash = Arrays.toString(digest.digest(hashInput.getBytes(StandardCharsets.UTF_8)));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaVerify.initVerify(base64toPublicKey(publicKey));
        ecdsaVerify.update(hash.getBytes("UTF-8"));

        return ecdsaVerify.verify(signatureBytes);
    }


    /**
     * Takes a EC public key encoded in base 64 and decodes it
     * @param base64key the base 64 key to decode
     * @return the decoded ECPublicKey
     * @throws KeyException if an error occurs deserializing the key
     */
    public static ECPublicKey base64toPublicKey(String base64key) throws KeyException {
        byte[] keyBytes = Base64.getDecoder().decode(base64key);
        try {
            X509EncodedKeySpec ks = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(ks);
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyException(e);
        }
    }

    public static ECPrivateKey base64toPrivateKey(String base64key) throws KeyException {
        byte[] keyBytes = Base64.getDecoder().decode(base64key);
        try {
            final KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            final PKCS8EncodedKeySpec encPrivKeySpec = new PKCS8EncodedKeySpec(keyBytes);
            return (ECPrivateKey) kf.generatePrivate(encPrivKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new KeyException(e);
        }
    }

    /**
     * Takes a EC public key and encodes it in base64
     * @param key the ECPublicKey to encode
     * @return the encoded key in base 64
     * @throws KeyException if an error occurs serializing the key
     */
    public static String publicKeyToBase64(ECPublicKey key) throws KeyException {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String privateKeyToBase64(ECPrivateKey key) throws KeyException {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }


}
