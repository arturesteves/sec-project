package pt.ulisboa.tecnico.sec.g19.hdscoin.client;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.net.URL;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;


public class ClientTests {


    @Test
    public void testRegister() {
        //TODO - actually make the test
        try {
            String ServerPublicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESM5RJvz4CL4aXzpo1NuWhIkfYW1QWAG5droc7oavOeiWyhBsjnxD+Z+WZ4Fm3R8+1zml14aIJAO7grCnXe0uGg==";
            ECPublicKey serverPublicKey = Utils.base64toPublicKey(ServerPublicKeyBase64);

            Security.addProvider(new BouncyCastleProvider());

            IClient client = new Client(new URL("http://localhost:4567"), serverPublicKey);
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
            keyPairGenerator.initialize(ecGenSpec, new SecureRandom());

            java.security.KeyPair pair = keyPairGenerator.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) pair.getPrivate();
            ECPublicKey publicKeyExpected = (ECPublicKey) pair.getPublic();


            client.register(privateKey, publicKeyExpected, 50);

        } catch(Exception ex) {
            System.out.println(ex);
        }
    }

    @Test
    public void testSendAmount() {
        IClient client;

    }


    @Test
    public void testCheckAccount() {
        IClient client;

    }


    @Test
    public void testReceiveAmount() {
        //Here we can create two users and send money from one to the other and test if we can receive the amount
        IClient client;
    }

    @Test
    public void testAudit() {
        IClient client;

    }


}
