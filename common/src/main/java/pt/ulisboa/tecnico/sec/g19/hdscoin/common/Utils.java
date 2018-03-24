package pt.ulisboa.tecnico.sec.g19.hdscoin.common;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Utils {

    private static final int NONCE_SIZE = 20;
    private static RandomString rndGen = new RandomString(NONCE_SIZE);

    public static String randomNonce() {
        return rndGen.nextString();
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
        return checkSignature(signature, hashInput, Serialization.base64toPublicKey(publicKey));
    }

    public static boolean checkSignature(String signature, String hashInput, ECPublicKey publicKey) throws SignatureException, KeyException, NoSuchProviderException, NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String hash = Arrays.toString(digest.digest(hashInput.getBytes(StandardCharsets.UTF_8)));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaVerify.initVerify(publicKey);
        ecdsaVerify.update(hash.getBytes("UTF-8"));

        return ecdsaVerify.verify(signatureBytes);
    }

    public static KeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecGenSpec, new SecureRandom());

        return keyPairGenerator.generateKeyPair();
    }
}
