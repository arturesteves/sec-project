package pt.ulisboa.tecnico.sec.g19.hdscoin.common;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.CantGenerateKeysException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.CantWritePublicKeyToFileException;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

public class Utils {

    // not working...
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

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

    // deprecated
    public static KeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecGenSpec, new SecureRandom());

        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateKeyPair (String entity) throws CantGenerateKeysException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
            keyPairGenerator.initialize(ecGenSpec, new SecureRandom());

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new CantGenerateKeysException(e);
        }
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        /*
        try {
            writePublicKeyToFile (entity, (ECPublicKey) keyPair.getPublic());
        } catch (CantWritePublicKeyToFileException e) {
            throw new CantGenerateKeysException(e);
        }
        */
        return keyPair;
    }

    private static void writePublicKeyToFile (String entity, ECPublicKey publicKey) throws CantWritePublicKeyToFileException{
        String filename = (entity.equals ("client") ? "clients-public-keys.keys" : "servers-public-keys.keys");
        String root = System.getProperty("user.dir");
        System.out.println("Root: " + root);    // return the client root path not the common
        String s = "C:\\Users\\artur\\Documents\\Projectos\\Mestrado\\1º Ano\\2º Semestre\\SEC\\common\\";
        String p = "src\\main\\java\\pt\\ulisboa\\tecnico\\sec\\g19\\hdscoin\\common\\resources\\keys\\";
        String f = s+p+filename;
        //ClassLoader cl = Utils.class.getClass().getClassLoader();
        //System.out.println(cl.getName());   // retornou null


        File directory = new File("./");
        System.out.println(directory.getAbsolutePath());    // returning the path of the client project ....

        //System.out.println(",,,," + cl.getResource("keys/servers-public-keys.keys").getFile());
        //URL url = Utils.class.getResource("/src/main/java/pt/ulisboa/tecnico/sec/g19/hdscoin/server")
        //URL resource = Utils.class.getResource("pt/ulisboa/tecnico/sec/g19/hdscoin/common/keys/" + filename);
        //System.out.print("RESOURCE::: " + resource.getFile());
            //// return some strange path
        ////URL url = Utils.class.getResource("/keys/servers-public-keys.keys");
        ////System.out.println(url.getFile());
        try {
            String publicKeyBase64 = Serialization.publicKeyToBase64 (publicKey);   // encode the public key into 64 base string
            FileWriter fw = new FileWriter(f, true); // true to append to file or create if doesn't exist
            BufferedWriter bw = new BufferedWriter(fw);
            PrintWriter out = new PrintWriter(bw);
            out.println(publicKeyBase64);

            // close
            out.flush();
            out.close();
            bw.close();
            fw.close();
        } catch (KeyException | IOException e) {
            e.printStackTrace ();
            throw new CantWritePublicKeyToFileException (e);
        }
    }

    public static void writeKeyPairToFile (String filepath, KeyPair keyPair) throws KeyException, IOException {
        String root = System.getProperty("user.dir");
        String publicKeyBase64 = Serialization.publicKeyToBase64 ( (ECPublicKey) keyPair.getPublic ());
        String privateKeyBase64 = Serialization.privateKeyToBase64 ( (ECPrivateKey) keyPair.getPrivate());

        System.out.println("Writing keys to '" + root + filepath);

        File file = new File (root + filepath);
        FileWriter fw;
        if (!file.createNewFile ()) {
            fw = new FileWriter(file,false);//if file exists overwrite it
        } else {
            fw = new FileWriter(file);
        }
        fw.write (publicKeyBase64 + "\n" + privateKeyBase64);
        fw.close();
    }



    // OK -  missing documentation
    public static ECPublicKey readPublicKeyFromFile (String filepath) throws KeyException, IOException{
        String root = System.getProperty("user.dir");

        ECPublicKey publicKey = null;

        FileReader fr = new FileReader (root + filepath);
        BufferedReader bf = new BufferedReader (fr);
        String line = bf.readLine(); // the public key is only in 1 line?
        publicKey = Serialization.base64toPublicKey(line);

        bf.close();
        fr.close();

        return publicKey;
    }

    public static ECPrivateKey readPrivateKeyFromFile (String filepath) throws KeyException, IOException{
        String root = System.getProperty("user.dir");
        ECPrivateKey privateKey = null;
        FileReader fr = new FileReader (root + filepath);
        BufferedReader bf = new BufferedReader (fr);
        bf.readLine(); //1st line
        privateKey = Serialization.base64toPrivateKey (bf.readLine ()); // read 2nd line that

        bf.close();
        fr.close();

        return privateKey;
    }

}
