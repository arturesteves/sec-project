package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.FailedToLoadKeys;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.InvalidAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception.InvalidLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures.Ledger;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.sql.Connection;
import java.sql.SQLException;

import spark.Request;
import spark.Response;
import static spark.Spark.post;
import static spark.Spark.get;

public class Main {

    public static final String FILE_PATH = "/src/main/java/pt/ulisboa/tecnico/sec/g19/hdscoin/server/keys";
    private static ECPublicKey serverPublicKey;
    private static ECPrivateKey serverPrivateKey;

    public static void main(String[] args) throws FailedToLoadKeys {

        Security.addProvider(new BouncyCastleProvider());
        try {
            loadKeys (args[0]);
        } catch (KeyException | IOException e) {
            System.out.println("ENTREI");
            throw new FailedToLoadKeys ("Failed to load keys from file. " + e.getMessage(), e);
        }

        try {
            Database.recreateSchema();
        } catch (SQLException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        post("/register", "application/json", (req, res) -> {

            try {
                Serialization.RegisterRequest request = Serialization.parse(req, Serialization.RegisterRequest.class);

                System.out.println("SIG: " + req.headers("SIGNATURE"));
                System.out.println("NONCE: " + req.headers("NONCE"));
                System.out.println("Key: " + request.key);
                System.out.println("Amount: " + request.amount);

                //Recreate the hash with the data received
                Boolean result = Utils.checkSignature(req.headers("SIGNATURE"), request.getSignable(), request.key);

                if (!result) {
                    res.status(401);
                    return "Hash does not match";
                }

                ///////////////////////////////////////////////////
                //We now know that the public key was sent by the owner of its respective private key.
                ///////////////////////////////////////////////////

                Serialization.Response response = new Serialization.Response();
                Connection conn = null;
                try {
                    conn = Database.getConnection();
                    Ledger ledger = new Ledger(conn, Serialization.base64toPublicKey(request.key), request.amount);
                    ledger.persist(conn);
                    conn.commit();
                    response.status = "ok";
                } catch (InvalidLedgerException | InvalidKeyException | InvalidAmountException ex) {
                    // these exceptions are the client's fault
                    response.status = "error";
                    if (conn != null) {
                        conn.rollback();
                    }
                }

                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.status = "error";
                return prepareResponse(serverPrivateKey, req, res, response);
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
                Boolean result = Utils.checkSignature(req.headers("SIGNATURE"), request.getSignable(), request.source);

                if (!result) {
                    res.status(401);
                    return "Hash does not match";
                }

                ///////////////////////////////////////////////////
                //We now know that the public key was sent by the owner of its respective private key.
                ///////////////////////////////////////////////////

                //Todo - Do Something with the data.


                ///////////////////////////////////////////////////
                Serialization.Response response = new Serialization.Response();
                response.status = "ok";

                return prepareResponse(serverPrivateKey, req, res, response);
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
                Serialization.Response response = new Serialization.Response();
                response.status = "ok";

                return prepareResponse(serverPrivateKey, req, res, response);

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

    private static String prepareResponse(ECPrivateKey privateKey, Request sparkRequest, Response sparkResponse, Serialization.Response response) throws JsonProcessingException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException {
        response.nonce = sparkRequest.headers("NONCE");
        if (response.statusCode < 0) {
            // try to guess a status code from the status string
            if (response.status.equals("ok")) {
                response.statusCode = 200;
            } else {
                response.statusCode = 400;
            }
        }
        String signature = Utils.generateSignature(response.getSignable(), privateKey);
        sparkResponse.status(response.statusCode);
        sparkResponse.header("SIGNATURE", signature);
        sparkResponse.type("application/json");
        return Serialization.serialize(response);
    }

    private static void loadKeys (String serverName) throws KeyException, IOException{
        String filepath = FILE_PATH + "/" + serverName + ".keys";
        serverPublicKey = Utils.readPublicKeyFromFile (filepath);
        serverPrivateKey = Utils.readPrivateKeyFromFile (filepath);
    }
}