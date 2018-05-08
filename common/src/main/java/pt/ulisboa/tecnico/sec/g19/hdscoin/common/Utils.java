package pt.ulisboa.tecnico.sec.g19.hdscoin.common;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.KeyGenerationException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.SignatureException;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.logging.*;

import static pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization.KEY_STORE__PASSWORD;


public class Utils {

    private static final int NONCE_SIZE = 20;
    private static RandomString rndGen = new RandomString (NONCE_SIZE);
    private static String KEY_STORE_INSTANCE = "BKS";

    static {
        Security.addProvider (new BouncyCastleProvider ());
    }

    public static String randomNonce () {
        return rndGen.nextString ();
    }

    public static String generateHashBase64(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance ("SHA-256");
            byte[] hashedBytes = (digest.digest (input.getBytes (StandardCharsets.UTF_8)));
            return Base64.getEncoder ().encodeToString (hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    //Returns a signature in base64 over an hash input
    public static String generateSignature (String hashInput, ECPrivateKey privateKey) throws SignatureException {
        try {
            MessageDigest digest = MessageDigest.getInstance ("SHA-256");
            String hash = Arrays.toString (digest.digest (hashInput.getBytes (StandardCharsets.UTF_8)));

            Signature ecdsaSign = Signature.getInstance ("SHA256withECDSA", "BC");
            ecdsaSign.initSign (privateKey);
            ecdsaSign.update (hash.getBytes ("UTF-8"));
            return new String (Base64.getEncoder ().encode (ecdsaSign.sign ()), StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | UnsupportedEncodingException | java.security.SignatureException e) {
            e.printStackTrace ();
            throw new SignatureException ("Couldn't sign the message. " + e.getMessage ());
        }
    }

    public static boolean checkSignature (String signature, String hashInput, String publicKey)
            throws SignatureException, KeyException {
        return checkSignature (signature, hashInput, Serialization.base64toPublicKey (publicKey));
    }

    public static boolean checkSignature (String signature, String hashInput, ECPublicKey publicKey)
            throws SignatureException {
        try {
            MessageDigest digest = MessageDigest.getInstance ("SHA-256");
            String hash = Arrays.toString (digest.digest (hashInput.getBytes (StandardCharsets.UTF_8)));

            byte[] signatureBytes = Base64.getDecoder ().decode (signature);
            Signature ecdsaVerify = Signature.getInstance ("SHA256withECDSA", "BC");
            ecdsaVerify.initVerify (publicKey);
            ecdsaVerify.update (hash.getBytes ("UTF-8"));

            return ecdsaVerify.verify (signatureBytes);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | UnsupportedEncodingException | java.security.SignatureException e) {
            throw new SignatureException ("Couldn't check the signature. " + e.getMessage ());
        }
    }

    public static KeyPair generateKeyPair () throws KeyGenerationException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec ("secp256r1");

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance ("ECDSA", "BC");
            keyPairGenerator.initialize (ecGenSpec, new SecureRandom ());

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new KeyGenerationException ("Couldn't generate a key pair. " + e.getMessage (), e);
        }
        return keyPairGenerator.generateKeyPair ();
    }

    public static ECPublicKey readPublicKeyFromFile (String filepath) throws KeyException, IOException {
        ECPublicKey publicKey = null;

        FileReader fr = new FileReader (filepath);
        BufferedReader bf = new BufferedReader (fr);
        String line = bf.readLine (); // the public key is only in 1 line?
        publicKey = Serialization.base64toPublicKey (line);

        bf.close ();
        fr.close ();

        return publicKey;
    }

    public static ECPrivateKey readPrivateKeyFromFile (String filepath) throws KeyException, IOException {
        ECPrivateKey privateKey = null;
        FileReader fr = new FileReader (filepath);
        BufferedReader bf = new BufferedReader (fr);
        bf.readLine (); //1st line
        privateKey = Serialization.base64toPrivateKey (bf.readLine ()); // read 2nd line that

        bf.close ();
        fr.close ();

        return privateKey;
    }

    public static void initLogger (Logger log) {
        try {
            Formatter formatter = new Formatter () {
                @Override public String format (LogRecord record) {
                    StringBuilder builder = new StringBuilder();
                    builder.append(record.getLevel() + ": ");
                    builder.append(formatMessage(record));
                    builder.append(System.lineSeparator());
                    return builder.toString();
                }
            };
            ConsoleHandler consoleHandler = new ConsoleHandler();
            FileHandler fileHandler = new FileHandler ("logs/log-" + log.getName () + ".log");
            fileHandler.setEncoding ("UTF-8");
            fileHandler.setLevel (Level.ALL);
            //fileHandler.setFormatter (new SimpleFormatter ());
            fileHandler.setFormatter (formatter);
            consoleHandler.setFormatter (formatter);
            log.addHandler (fileHandler);
            log.addHandler(consoleHandler);
            log.setUseParentHandlers(false);    // stop printing the date time line
        } catch (IOException e) {
            e.printStackTrace ();
        }
    }

    public static int numberOfFaultsSupported(int numberOfReplicas) {
        return (numberOfReplicas - 1) / 3;
    }

    ////////////////////////////////////////////
    //// handle keystore
    ////////////////////////////////////////////

    public static KeyStore initKeyStore (String filepath)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException{

        KeyStore keyStore = KeyStore.getInstance (KEY_STORE_INSTANCE);
        File file = new File(filepath);
        if (file.exists ()) {
            FileInputStream fis = new FileInputStream(filepath);
            keyStore.load (fis, KEY_STORE__PASSWORD.toCharArray ());
        } else {
            // first time
            keyStore.load (null, KEY_STORE__PASSWORD.toCharArray ());
        }
        return keyStore;
    }

    public static void savePrivateKeyToKeyStore (KeyStore keyStore, String alias, String password,
                                                 ECPrivateKey privateKey, java.security.cert.Certificate cert)
            throws KeyStoreException {

        keyStore.setKeyEntry (alias, privateKey, password.toCharArray (), new Certificate[] { cert });
    }

    public static X509Certificate generateCertificate(KeyPair keyPair)
            throws NoSuchAlgorithmException, CertificateEncodingException, NoSuchProviderException, InvalidKeyException,
            java.security.SignatureException {

        X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
        cert.setSerialNumber(BigInteger.valueOf(1));   //or generate a random number
        cert.setSubjectDN(new X509Principal ("CN=localhost"));  //see examples to add O,OU etc
        cert.setIssuerDN(new X509Principal("CN=localhost")); //same since it is self-signed
        cert.setPublicKey(keyPair.getPublic());
        Calendar c1 = Calendar.getInstance ();
        Calendar c2 = Calendar.getInstance ();
        c1.set (2018, 1, 1);
        c2.set (2019, 1, 1);
        cert.setNotBefore(c1.getTime ());
        cert.setNotAfter(c2.getTime ());
        cert.setSignatureAlgorithm("SHA256withECDSA");
        PrivateKey signingKey = keyPair.getPrivate();
        return cert.generate(signingKey, "BC");
    }

    public static void storeKeyStore(KeyStore keyStore, String filepath)
            throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        FileOutputStream fos = new FileOutputStream(filepath);
        keyStore.store (fos, KEY_STORE__PASSWORD.toCharArray ());
        fos.close ();
    }

    public static ECPrivateKey loadPrivateKeyFromKeyStore(String filepath, String alias, String password)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableKeyException {

        FileInputStream fis = new FileInputStream(filepath);
        KeyStore keyStore = KeyStore.getInstance(KEY_STORE_INSTANCE);
        keyStore.load(fis, KEY_STORE__PASSWORD.toCharArray());
        fis.close();
        return (ECPrivateKey) keyStore.getKey(alias, password.toCharArray());
    }

    public static ECPublicKey loadPublicKeyFromKeyStore(KeyStore keyStore, String alias) throws KeyStoreException {
        return (ECPublicKey) keyStore.getCertificate (alias).getPublicKey ();
    }
}
