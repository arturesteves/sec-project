package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static spark.Spark.post;
import static spark.Spark.get;

public class Main {

    //Hardcoded for testing purposes
    private static final String serverPrivateKeyBase64 = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgBG/UwLmbiIGWOH7lzLQT5f7cR9pN3dCpzhc2uqX74y+gCgYIKoZIzj0DAQehRANCAARIzlEm/PgIvhpfOmjU25aEiR9hbVBYAbl2uhzuhq856JbKEGyOfEP5n5ZngWbdHz7XOaXXhogkA7uCsKdd7S4a";
    private static final String serverPublicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESM5RJvz4CL4aXzpo1NuWhIkfYW1QWAG5droc7oavOeiWyhBsjnxD+Z+WZ4Fm3R8+1zml14aIJAO7grCnXe0uGg==";


    public static void main(String[] args) throws KeyException {
        Security.addProvider(new BouncyCastleProvider());
        //Server keys for signing
        ECPublicKey serverPublicKey = Serialization.base64toPublicKey(serverPublicKeyBase64);
        ECPrivateKey serverPrivateKey = Serialization.base64toPrivateKey(serverPrivateKeyBase64);

        post("/register", "application/json", (req, res) -> {

            try {
                Serialization.RegisterRequest request = Serialization.parse(req, Serialization.RegisterRequest.class);

                System.out.println("SIG: " + req.headers("SIGNATURE"));
                System.out.println("NONCE: " + req.headers("NONCE"));
                System.out.println("Key: " + request.key);
                System.out.println("Amount: " + request.amount);

                //Recreate the hash with the data received
                Boolean result = Utils.checkSignature(req.headers("SIGNATURE"),
                        req.headers("NONCE") + request.key + request.amount,
                        request.key);

                if (!result) {
                    res.status(401);
                    return "Hash does not match";
                }

                ///////////////////////////////////////////////////
                //We now know that the public key was sent by the owner of its respective private key.
                ///////////////////////////////////////////////////

                //todo - DO stuff with the data

                ///////////////////////////////////////////////////

                String signature = Utils.generateSignature(req.headers("NONCE"), serverPrivateKey);
                res.status(200);
                res.header("SIGNATURE", signature);
                res.header("NONCE", req.headers("NONCE"));

                return "success";

            } catch (Exception ex) {
                res.status(200);
                res.type("application/json");
                throw ex;
            }
        });

        post("/sendAmount", "application/json", (req, res) -> {

            try {
                Serialization.SendAmountRequest request = Serialization.parse(req, Serialization.SendAmountRequest.class);

                System.out.println("SIG: " + req.headers("SIGNATURE"));
                System.out.println("NONCE: " + req.headers("NONCE"));
                System.out.println("Source: " + request.source);
                System.out.println("Destination: " + request.destination);
                System.out.println("Amount: " + request.amount);

                //Recreate the hash with the data received
                Boolean result = Utils.checkSignature(req.headers("SIGNATURE"),
                        req.headers("NONCE") + request.source + request.destination + request.amount,
                        request.source);

                if (!result) {
                    res.status(401);
                    return "Hash does not match";
                }

                ///////////////////////////////////////////////////
                //We now know that the public key was sent by the owner of its respective private key.
                ///////////////////////////////////////////////////

                //Todo - Do Something with the data.


                ///////////////////////////////////////////////////

                String signature = Utils.generateSignature(req.headers("NONCE"), serverPrivateKey);
                res.status(200);
                res.header("SIGNATURE", signature);
                res.header("NONCE", req.headers("NONCE"));

                return "success";

            } catch (Exception ex) {
                res.status(200);
                res.type("application/json");
                throw ex;
            }

        });

        get("/checkAccount/:key", "application/json", (req, res) -> {
            //Todo - Do Something with the data.
            System.out.println("Received account Public key: " + req.params(":key"));

            res.status(200);
            return "Success";
        });

        post("/receiveAmount", "application/json", (req, res) -> {

            try {
                Serialization.ReceiveAmountRequest request = Serialization.parse(req, Serialization.ReceiveAmountRequest.class);

                //Recreate the hash with the data received
                Boolean result = Utils.checkSignature(req.headers("SIGNATURE"),
                        req.headers("NONCE") + request.source,
                        request.source);

                if (!result) {
                    res.status(401);
                    return "Hash does not match";
                }

                ///////////////////////////////////////////////////
                //We now know that the public key was sent by the owner of its respective private key.
                ///////////////////////////////////////////////////

                //Todo - Do Something with the data.
                System.out.println("Received Source Public key: " + request.source);

                ///////////////////////////////////////////////////

                String signature = Utils.generateSignature(req.headers("NONCE"), serverPrivateKey);
                res.status(200);
                res.header("SIGNATURE", signature);
                res.header("NONCE", req.headers("NONCE"));

                return "success";

            } catch (Exception ex) {
                res.status(200);
                res.type("application/json");
                throw ex;
            }

        });

        get("/audit/:key", "application/json", (req, res) -> {
            //Todo - Do Something with the data.
            System.out.println("Received account Public key: " + req.params(":key"));

            res.status(200);
            return "Success";
        });
    }
}