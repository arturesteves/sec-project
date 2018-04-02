package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.CantGenerateSignatureException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.InvalidAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.InvalidLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.MissingLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures.Ledger;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.logging.*;

import pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures.Transaction;
import spark.Request;
import spark.Response;

import static pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization.StatusMessage.*;
import static spark.Spark.post;
import static spark.Spark.get;


public class Main {
    private final static Logger log = Logger.getLogger (Main.class.getName ());

    public static final String FILE_PATH = "/src/main/java/pt/ulisboa/tecnico/sec/g19/hdscoin/server/keys";
    private static ECPublicKey serverPublicKey;
    private static ECPrivateKey serverPrivateKey;

    public static void main(String[] args) throws FailedToLoadKeysException {
        // set Logger
        Utils.initLogger (log);
        Security.addProvider(new BouncyCastleProvider());
        log.log (Level.CONFIG, "Added bouncy castle security provider.");

        try {
            loadKeys (args[0]);
            log.log (Level.INFO, "Loaded keys of the server.");

        } catch (KeyException | IOException e) {
            log.log (Level.SEVERE, "Failed to load keys from file. " + e);
            throw new FailedToLoadKeysException("Failed to load keys from file. " + e.getMessage(), e);
        }

        try {
            Database.recreateSchema();
            log.log (Level.INFO, "Recreate database schema.");
        } catch (SQLException e) {
            log.log (Level.SEVERE, "Failed to recreate database schema. " + e);
            e.printStackTrace();
            System.exit(-1);
        }

        post("/register", "application/json", (req, res) -> {

            try {
                Serialization.RegisterRequest request = Serialization.parse(req, Serialization.RegisterRequest.class);
                log.log (Level.INFO, "Request received at: /register \n" +
                        "data on the request:" +
                        "SIGNATURE: " + req.headers("SIGNATURE") + "\n" +
                        "NONCE: " + req.headers("NONCE") + "\n" +
                        "CLIENT BASE 64 PUBLIC KEY: " + request.key + "\n" +
                        "AMOUNT: " + request.amount);

                //Recreate the hash with the data received
                Boolean result = Utils.checkSignature(req.headers("SIGNATURE"), request.getSignable(),
                                                        request.key);

                Serialization.Response response = new Serialization.Response();

                if (!result) {
                    res.status(401);
                    log.log (Level.WARNING, "The messange received from the client doesn't match with the " +
                            "signature of the message.");
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                ///////////////////////////////////////////////////
                //We now know that the public key was sent by the owner of its respective private key.
                ///////////////////////////////////////////////////

                Connection conn = null;
                try {
                    conn = Database.getConnection();
                    Ledger ledger = new Ledger(conn, Serialization.base64toPublicKey(request.key), request.amount);
                    ledger.persist(conn);
                    conn.commit();
                    response.status = SUCCESS;
                    log.log (Level.INFO, "Initialized a new ledger with the base 64 public key: " + request.key);
                } catch (SQLException e) {
                    // servers fault
                    log.log (Level.SEVERE, "Error related to the database. " + e);
                    response.status = ERROR_SERVER_ERROR;
                }
                // these exceptions are the client's fault
                catch (InvalidLedgerException e) {
                    response.status = ERROR_INVALID_LEDGER;
                } catch (InvalidAmountException e) {
                    response.status = ERROR_INVALID_AMOUNT;
                } catch (InvalidKeyException e) {
                    response.status = ERROR_INVALID_KEY;
                } finally {
                    if (!response.status.equals(SUCCESS) && conn != null) {
                        conn.rollback ();
                        log.log (Level.SEVERE, "The ledger created with the following public key was not " +
                                "persisted. Public Key: " + request.key);
                    }
                }

                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.status = ERROR_SERVER_ERROR;
                log.log (Level.SEVERE, "Error on processing a register request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        post("/sendAmount", "application/json", (req, res) -> {

            try {
                Serialization.SendAmountRequest request = Serialization.parse(req,
                                                                Serialization.SendAmountRequest.class);
                log.log (Level.INFO, "Request received at: /sendAmount \n" +
                        "data on the request:" +
                        "SIGNATURE: " + req.headers("SIGNATURE") + "\n" +
                        "NONCE: " + req.headers("NONCE") + "\n" +
                        "AMOUNT:" + request.amount + "\n" +
                        "SOURCE CLIENT BASE 64 PUBLIC KEY: " + request.source + "\n" +
                        "TARGET CLIENT BASE 64 PUBLIC KEY: " + request.target + "\n");

                //Recreate the hash with the data received
                Boolean result = Utils.checkSignature(req.headers("SIGNATURE"), request.getSignable(),
                                                        request.source);

                Serialization.Response response = new Serialization.Response ();

                if (!result) {
                    res.status(401);
                    log.log (Level.WARNING, "The messange received from the client doesn't match with the " +
                            "signature of the message.");
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                ///////////////////////////////////////////////////
                //We now know that the public key was sent by the owner of its respective private key.
                ///////////////////////////////////////////////////

                Connection conn = null;
                try {
                    conn = Database.getConnection ();
                    Ledger sourceLedger = Ledger.load (conn, Serialization.base64toPublicKey (request.source));
                    Ledger targetLedger = Ledger.load (conn, Serialization.base64toPublicKey (request.target));

                    Transaction transaction = new Transaction (conn, sourceLedger, targetLedger, request.amount,
                                                req.headers("NONCE"), req.headers("SIGNATURE"),
                                                request.previousSignature, Transaction.TransactionTypes.SENDING);

                    transaction.persist (conn);
                    conn.commit ();
                    response.status = SUCCESS;
                    log.log (Level.INFO, "Transaction created with success.");
                } catch (SQLException e) {
                    // servers fault
                    log.log (Level.SEVERE, "Error related to the databas. " + e);
                    response.status = ERROR_SERVER_ERROR;
                } finally {
                    if (!response.status.equals(SUCCESS) && conn != null) {
                        conn.rollback ();
                        log.log (Level.SEVERE, "The transaction created was not persisted, due to an error.");
                    }
                }

                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.status = ERROR_SERVER_ERROR;
                log.log (Level.SEVERE, "Error on processing a register request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        get("/checkAccount", "application/json", (req, res) -> {
            try {
                String b64PublicKey = req.queryParamOrDefault ("publickey", "")
                                        .replace (" ", "+");    // to be sure
                log.log (Level.INFO, "Request received at: /checkAccount \n" +
                        "data on the request:" +
                        "public key: " + b64PublicKey);

                Serialization.CheckAccountResponse response = new Serialization.CheckAccountResponse ();
                Connection conn = null;
                try {
                    ECPublicKey clientPublicKey = Serialization.base64toPublicKey (b64PublicKey);
                    conn = Database.getConnection ();
                    Ledger ledger = Ledger.load (conn, clientPublicKey);
                    System.out.println("Pendin" + ledger.getPendingTransactions (conn, clientPublicKey));
                    response.balance = ledger.getAmount ();
                    response.pendingTransactions = ledger.getPendingTransactions (conn, clientPublicKey);
                    System.out.printf("Balance: " + response.balance);

                    response.status = SUCCESS;
                    log.log (Level.INFO, "Successful check account operation of the ledger with the " +
                            "following public key in base 64: " + b64PublicKey);
                } catch (SQLException e) {
                    // servers fault
                    log.log (Level.SEVERE, "Error related to the database. " + e);
                    response.status = ERROR_SERVER_ERROR;
                }
                // these exceptions are the client's fault
                catch (MissingLedgerException e) {
                    response.status = ERROR_INVALID_LEDGER;
                } catch (InvalidKeyException e) {
                    response.status = ERROR_INVALID_KEY;
                }
                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                res.status (500);
                Serialization.Response response = new Serialization.Response ();
                response.status = ERROR_SERVER_ERROR;
                log.log (Level.SEVERE, "Error on processing a check account request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        post("/receiveAmount", "application/json", (req, res) -> {

            try {
                Serialization.ReceiveAmountRequest request = Serialization.parse(req,
                                                                Serialization.ReceiveAmountRequest.class);

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
                response.status = SUCCESS;

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

    private static String prepareResponse(ECPrivateKey privateKey, Request sparkRequest, Response sparkResponse, Serialization.Response response) throws JsonProcessingException, CantGenerateSignatureException {
        response.nonce = sparkRequest.headers("NONCE");
        if (response.statusCode < 0) {
            // try to guess a status code from the status string
            if (response.status.equals (SUCCESS)) {
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