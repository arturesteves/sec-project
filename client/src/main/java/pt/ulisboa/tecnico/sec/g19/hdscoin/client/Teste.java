package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.net.URL;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class Teste {

    public static void main(String[] args) {
        try {
            String ServerPublicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESM5RJvz4CL4aXzpo1NuWhIkfYW1QWAG5droc7oavOeiWyhBsjnxD+Z+WZ4Fm3R8+1zml14aIJAO7grCnXe0uGg==";
            ECPublicKey serverPublicKey = Serialization.base64toPublicKey(ServerPublicKeyBase64);

            Security.addProvider(new BouncyCastleProvider());

            IClient client = new Client(new URL("http://localhost:4567"), serverPublicKey);

            KeyPair pairA = Utils.generateKeyPair();
            ECPrivateKey privateKeyA = (ECPrivateKey) pairA.getPrivate();
            ECPublicKey publicKeyExpectedA = (ECPublicKey) pairA.getPublic();

            KeyPair pairB = Utils.generateKeyPair();
            ECPrivateKey privateKeyB = (ECPrivateKey) pairB.getPrivate();
            ECPublicKey publicKeyExpectedB = (ECPublicKey) pairB.getPublic();

            client.register(publicKeyExpectedA, privateKeyA, 50);
            System.out.println("Registered successfully");
            //client.sendAmount(privateKeyA, publicKeyExpectedA, publicKeyExpectedB, 20);
            System.out.println("Amount sent successfully");

        } catch(Exception ex) {
            System.out.println(ex);
        }
    }


}
