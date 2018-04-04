package pt.ulisboa.tecnico.sec.g19.hdscoin.common;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.KeyGenerationException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.SignatureException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.*;

public class Utils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final int NONCE_SIZE = 20;
    private static RandomString rndGen = new RandomString(NONCE_SIZE);


    public static String randomNonce() {
        return rndGen.nextString();
    }

    //Returns a signature in base64 over an hash input
    public static String generateSignature(String hashInput, ECPrivateKey privateKey) throws SignatureException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String hash = Arrays.toString(digest.digest(hashInput.getBytes(StandardCharsets.UTF_8)));

            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(hash.getBytes("UTF-8"));
            return new String(Base64.getEncoder().encode(ecdsaSign.sign()), StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | UnsupportedEncodingException | java.security.SignatureException e) {
            throw new SignatureException("Couldn't sign the message. " + e.getMessage (), e);
        }
    }

    public static boolean checkSignature(String signature, String hashInput, String publicKey) throws SignatureException, KeyException {
        return checkSignature(signature, hashInput, Serialization.base64toPublicKey(publicKey));
    }

    public static boolean checkSignature(String signature, String hashInput, ECPublicKey publicKey) throws SignatureException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String hash = Arrays.toString(digest.digest(hashInput.getBytes(StandardCharsets.UTF_8)));

            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(hash.getBytes("UTF-8"));

            return ecdsaVerify.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | UnsupportedEncodingException | java.security.SignatureException e) {
            throw new SignatureException("Couldn't check the signature. " + e.getMessage (), e);
        }
    }

    public static KeyPair generateKeyPair () throws KeyGenerationException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
            keyPairGenerator.initialize(ecGenSpec, new SecureRandom());

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new KeyGenerationException("Couldn't generate a key pair. " + e.getMessage(), e);
        }
        return keyPairGenerator.generateKeyPair();
    }

    public static void writeKeyPairToFile (String filepath, KeyPair keyPair) throws KeyException, IOException {
        String publicKeyBase64 = Serialization.publicKeyToBase64 ( (ECPublicKey) keyPair.getPublic ());
        String privateKeyBase64 = Serialization.privateKeyToBase64 ( (ECPrivateKey) keyPair.getPrivate());

        File file = new File (filepath);
        FileWriter fw;
        if (!file.createNewFile ()) {
            fw = new FileWriter(file,false);//if file exists overwrite it
        } else {
            fw = new FileWriter(file);
        }
        fw.write (publicKeyBase64 + "\n" + privateKeyBase64);
        fw.close();
    }

    public static ECPublicKey readPublicKeyFromFile (String filepath) throws KeyException, IOException{
        ECPublicKey publicKey = null;

        FileReader fr = new FileReader (filepath);
        BufferedReader bf = new BufferedReader (fr);
        String line = bf.readLine(); // the public key is only in 1 line?
        publicKey = Serialization.base64toPublicKey(line);

        bf.close();
        fr.close();

        return publicKey;
    }

    public static ECPrivateKey readPrivateKeyFromFile (String filepath) throws KeyException, IOException{
        ECPrivateKey privateKey = null;
        FileReader fr = new FileReader (filepath);
        BufferedReader bf = new BufferedReader (fr);
        bf.readLine(); //1st line
        privateKey = Serialization.base64toPrivateKey (bf.readLine ()); // read 2nd line that

        bf.close();
        fr.close();

        return privateKey;
    }

    public static void initLogger (Logger log) {
        ConsoleHandler consoleHandler = new ConsoleHandler ();
        consoleHandler.setLevel (Level.ALL);
        consoleHandler.setFormatter (new SimpleFormatter());
        try {
            FileHandler fileHandler = new FileHandler ("logs.log");
            fileHandler.setEncoding("UTF-8");
            fileHandler.setLevel(Level.ALL);
            fileHandler.setFormatter(new SimpleFormatter ());
            log.addHandler (fileHandler);

        } catch (IOException e) {
            e.printStackTrace ();
        }
        log.addHandler (consoleHandler);
        log.setLevel(Level.ALL);
    }
}
