package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.ServerInfo;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.SignatureException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.FailedToLoadKeysException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.InvalidAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.InvalidLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.InvalidValueException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.MissingLedgerException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions.MissingTransactionException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures.Ledger;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.*;
import java.util.logging.*;

import pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures.Transaction;
import pt.ulisboa.tecnico.sec.g19.hdscoin.server.structures.VerifiableLedger;
import spark.Request;
import spark.Response;

import static pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization.SERVER_PREFIX;
import static pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization.StatusMessage.*;
import static spark.Spark.*;


public class Main {
    // contains the protocol and host used and the initial port used
    public static final String GENERIC_URL = "http://localhost:4570";

    private static Logger log;

    private static KeyStore keyStore;
    private static String password;
    private static ECPublicKey serverPublicKey;
    private static ECPrivateKey serverPrivateKey;

    private static Object ledgerLock = new Object();

    private static List<ServerInfo> servers;

    private static Map<String, Map<ServerInfo, Ledger>> listening;

    
    public static void main(String[] args) throws FailedToLoadKeysException {

        try {
            // fetch all relevant command line arguments
            String serverName = args[0];
            int port = Integer.parseInt (args[1]);
            int numberOfServers = Integer.parseInt (args[2]);
            String password = args[3];

            log = Logger.getLogger(serverName + "_logs");
            Ledger.log = Logger.getLogger(serverName + "_" + Ledger.class.getName() + "_logs");
            Transaction.log = Logger.getLogger(serverName + "_" + Transaction.class.getName() + "_logs");

            // set Loggers
            Utils.initLogger(log);
            Utils.initLogger(Ledger.log);
            Utils.initLogger(Transaction.log);

            log.log(Level.INFO, "Server identification: " + serverName);
            log.log(Level.INFO, "Using port number: " + port);
            log.log(Level.INFO, "Number of replicas: " + numberOfServers);

            String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\common";
            String filepath = root + Serialization.COMMON_PACKAGE_PATH + "\\" + Serialization.KEY_STORE_FILE_NAME;
            Path path = Paths.get (filepath).normalize();

            // init key store
            KeyStore keyStore = Utils.initKeyStore (path.toString ());

            // load keys
            serverPrivateKey = Utils.loadPrivateKeyFromKeyStore (path.toString (), serverName, password);
            serverPublicKey = Utils.loadPublicKeyFromKeyStore (keyStore, serverName);
                              Utils.loadPublicKeyFromKeyStore (keyStore, serverName);


            // set database name
            Database.setDatabaseName(serverName + "_");

            Security.addProvider(new BouncyCastleProvider());
            log.log(Level.CONFIG, "Added bouncy castle security provider.");

            port(port);

            //Getting the replica servers information given by argument.
            servers = getServersInfoFromKeyStore(new URL (GENERIC_URL), numberOfServers, path.toString (), serverName);
            log.log(Level.INFO, "List of replicas: " + servers);
            listening = new HashMap<> ();

            System.out.println ("Replica listening on port: " + port);

        } catch (IOException e) {
            log.log(Level.SEVERE, "Failed to load keys from file. " + e);
            throw new FailedToLoadKeysException("Failed to load keys from file. " + e.getMessage(), e);
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            Database.recreateSchema();
            log.log(Level.INFO, "Recreate database schema.");
        } catch (SQLException e) {
            log.log(Level.SEVERE, "Failed to recreate database schema. " + e);
            e.printStackTrace();
            System.exit(-1);
        }


        post("/register", "application/json", (req, res) -> {

            Serialization.RegisterRequest request = null;
            try {
                request = Serialization.parse(req, Serialization.RegisterRequest.class);
                Serialization.Response response = new Serialization.Response();
                response.nonce = request.initialTransaction.nonce;
                if (request.initialTransaction == null) {
                    response.status = ERROR_MISSING_PARAMETER;
                    log.log(Level.WARNING, "Missing initial transaction on register request.");
                    return prepareResponse(serverPrivateKey, req, res, response);
                }
                log.log(Level.INFO, "Request received at: /register \n" +
                        "data on the request: \n" +
                        "\tSIGNATURE: " + req.headers(Serialization.SIGNATURE_HEADER_NAME) + "\n" +
                        "\tNONCE: " + request.initialTransaction.nonce + "\n" +
                        "\tCLIENT BASE 64 PUBLIC KEY: " + request.initialTransaction.source + "\n" +
                        "\tAMOUNT: " + request.initialTransaction.amount);

                boolean result = false; // false to defend
                try {
                    //Recreate the hash with the data received
                    result = Utils.checkSignature(
                            req.headers(Serialization.SIGNATURE_HEADER_NAME),
                            request.getSignable(),
                            request.initialTransaction.source);

                    System.out.println("SIGN val: " + result);
                } catch (SignatureException e) {
                    log.log(Level.WARNING, "The signature of the message received from the client doesn't match " +
                            "with the signature of the message generated by the server. " + e);
                }

                if (!result) {
                    res.status(401);
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    log.log(Level.WARNING, "Client signature not verified.");
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                ///////////////////////////////////////////////////
                //We now know that the register request was sent by the owner of its respective private key.
                ///////////////////////////////////////////////////

                Connection conn = null;
                try {
                    conn = Database.getConnection();
                    // mutual exclusion is necessary to ensure the new ledger ID obtained in "new Ledger"
                    // is still correct/"fresh" when "ledger.persist" is called.
                    synchronized (ledgerLock) {
                        Ledger ledger = new Ledger(conn, Serialization.base64toPublicKey(request.initialTransaction.source), request.initialTransaction);
                        ledger.persist(conn);
                        conn.commit();
                    }
                    response.status = SUCCESS;
                    log.log(Level.INFO, "Initialized a new ledger with the base 64 public key: " + request.initialTransaction.source);
                } catch (SQLException e) {
                    // servers fault
                    log.log(Level.SEVERE, "Error related to the database. " + e);
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
                        conn.rollback();
                        log.log(Level.SEVERE, "The ledger created with the following public key was not " +
                                "persisted. Public Key: " + request.initialTransaction.source);
                    }
                }

                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.nonce = (request != null && request.initialTransaction != null ? request.initialTransaction.nonce : "");
                response.status = ERROR_SERVER_ERROR;
                log.log(Level.SEVERE, "Error on processing a register request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        post("/completeRead", "application/json", (req, res) -> {

            Serialization.ReadCompleteRequest request = null;
            try {
                request = Serialization.parse(req, Serialization.ReadCompleteRequest.class);
                Serialization.Response response = new Serialization.Response();
                log.log(Level.INFO, "Request received at: /completeRead \n" +
                        "data on the request: \n" +
                        "\tSIGNATURE: " + req.headers(Serialization.SIGNATURE_HEADER_NAME) + "\n" +
                        "\tNONCE: " + request.nonce + "\n" +
                        "\tNonce of request to clean value: " + request.requestNonce);

                boolean result = false; // false to defend
                try {
                    //Recreate the hash with the data received
                    result = Utils.checkSignature(
                            req.headers(Serialization.SIGNATURE_HEADER_NAME),
                            request.getSignable(),
                            request.publicKeyBase64);

                    System.out.println("SIGN val: " + result);
                } catch (SignatureException e) {
                    log.log(Level.WARNING, "The signature of the message received from the client doesn't match " +
                            "with the signature of the message generated by the server. " + e);
                }

                if (!result) {
                    res.status(401);
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    log.log(Level.WARNING, "Client signature not verified.");
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                ///////////////////////////////////////////////////
                //We now know that the register request was sent by the owner of its respective private key.
                ///////////////////////////////////////////////////

                /*
                Connection conn = null;
                try {
                    conn = Database.getConnection();
                    // mutual exclusion is necessary to ensure the new ledger ID obtained in "new Ledger"
                    // is still correct/"fresh" when "ledger.persist" is called.
                    synchronized (ledgerLock) {
                        Ledger ledger = new Ledger(conn, Serialization.base64toPublicKey(request.initialTransaction.source), request.initialTransaction);
                        ledger.persist(conn);
                        conn.commit();
                    }
                    response.status = SUCCESS;
                    log.log(Level.INFO, "Initialized a new ledger with the base 64 public key: " + request.initialTransaction.source);
                } catch (SQLException e) {
                    // servers fault
                    log.log(Level.SEVERE, "Error related to the database. " + e);
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
                        conn.rollback();
                        log.log(Level.SEVERE, "The ledger created with the following public key was not " +
                                "persisted. Public Key: " + request.publicKeyBase64);
                    }
                }

                */

                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.nonce = (request != null ? request.nonce : "");
                response.status = ERROR_SERVER_ERROR;
                log.log(Level.SEVERE, "Error on processing a register request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        ////////////////////////////////////////////////
        //// WRITE OPERATIONS
        ////////////////////////////////////////////////

        post("/sendAmount", "application/json", (req, res) -> {
            try {
                Serialization.SendAmountRequest request = Serialization.parse(req,
                        Serialization.SendAmountRequest.class);
                log.log(Level.INFO, "\n\n------------------------------------");
                log.log(Level.INFO, "Request received at: /sendAmount");
                log.log(Level.INFO,"data on the request:\n" +
                        "SIGNATURE: " + req.headers(Serialization.SIGNATURE_HEADER_NAME) + "\n" +
                        "NONCE: " + request.transaction.nonce + "\n" +
                        "AMOUNT:" + request.transaction.amount + "\n" +
                        "SOURCE CLIENT BASE 64 PUBLIC KEY: " + request.transaction.source + "\n" +
                        "TARGET CLIENT BASE 64 PUBLIC KEY: " + request.transaction.target);
                log.log(Level.INFO, "\n");
                Serialization.Response response = new Serialization.Response();
                response.nonce = request.transaction.nonce;

                //Recreate the hash with the data received
                boolean result = Utils.checkSignature(
                        req.headers(Serialization.SIGNATURE_HEADER_NAME),
                        request.getSignable(),
                        request.transaction.source);

                if (!result) {
                    res.status(401);
                    log.log(Level.WARNING, "Mismatch in request signatures");
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                ///////////////////////////////////////////////////
                //We now know that the transaction was created by the owner of its respective private key.
                ///////////////////////////////////////////////////

                log.log(Level.INFO, "Transaction signature: " + request.transaction.getSignable());
                // now check the transaction itself
                result = Utils.checkSignature(
                        request.transaction.signature,
                        request.transaction.getSignable(),
                        request.transaction.source);

                if (!result) {
                    res.status(401);
                    log.log(Level.WARNING, "Mismatch in transaction signatures");
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                Connection conn = null;
                try {
                    conn = Database.getConnection();
                    Ledger sourceLedger = Ledger.load(conn, Serialization.base64toPublicKey(request.transaction.source));

                    // check the timestamp of the request
                    if (sourceLedger.getTimestamp () >= request.ledger.timestamp) {
                        res.status(401);
                        log.log(Level.WARNING, "Older operation");
                        response.status = ERROR_INVALID_LEDGER;
                        return prepareResponse(serverPrivateKey, req, res, response);
                    }


                    //////////////////
                    // verify if the hash of the ledger received match the ledger currently persisted
                    //////////////////

                    // hash the local ledger
                    List<Transaction> localTransactions = sourceLedger.getAllTransactions (conn);
                    List<Serialization.Transaction> localSerializableTransactions = serializeTransactions (localTransactions);
                    VerifiableLedger localLedger = new VerifiableLedger (localSerializableTransactions);
                    String localLedgerHash = Utils.generateHashBase64 (localLedger.getHashable ());

                    // hash the ledger received
                    VerifiableLedger receivedLedger = new VerifiableLedger (request.ledger.transactions);
                    String receivedLedgerHash = Utils.generateHashBase64 (receivedLedger.getHashable ());

                    if (localLedgerHash == null || receivedLedgerHash == null) {
                        res.status(401);
                        log.log(Level.WARNING, "Couldn't hash the transactions.");
                        response.status = ERROR_SERVER_ERROR;   // could be better
                        return prepareResponse(serverPrivateKey, req, res, response);
                    }

                    log.log(Level.INFO, "---------------------------");
                    log.log(Level.INFO, "Ledger received:");
                    log.log(Level.INFO, "timestamp: " + request.ledger.timestamp);
                    log.log(Level.INFO, "signable: " + receivedLedger.getHashable ());
                    log.log(Level.INFO, "Sign: " + receivedLedgerHash);
                    log.log(Level.INFO, "---------------------------");
                    log.log(Level.INFO, "\n");
                    log.log(Level.INFO, "Local ledger: ");
                    log.log(Level.INFO, "timestamp: " + sourceLedger.getTimestamp ());
                    log.log(Level.INFO, "signable: " + localLedger.getHashable ());
                    log.log(Level.INFO, "Sign: " + localLedgerHash);
                    log.log(Level.INFO, "---------------------------");
                    log.log(Level.INFO, "\n");


                    // if not equal the local replica is ahead or behind the current agreed ledger by the majority of replicas
                    if (!localLedgerHash.equals (receivedLedgerHash)) {

                        int endIndex = localSerializableTransactions.size () - 1;
                        // remove the last transaction from the last before hashing
                        VerifiableLedger subLocalLedger = new VerifiableLedger (localSerializableTransactions.subList (endIndex - 1, endIndex));
                        String subLocalLedgerHash = Utils.generateHashBase64 (subLocalLedger.getHashable ());

                        // check if the ledger contained one operation that wasn't completed by a majority
                        if (subLocalLedgerHash.equals (receivedLedgerHash)) {
                            // remove the last transaction from the database
                            Transaction.removeTransaction (conn, localTransactions.get (localTransactions.size () - 1).getId ());
                            conn.commit (); // commit this change
                            // continue, to try to perform the operation now on a update ledger which is agreed by the majority
                        } else {
                            /*
                            has the ledger on a replica can only have at most a operation at the top of the ledger
                            that wasn't completed by a majority when this stage is reached it means that the replica
                            is behind the current agreed state of a ledger.
                            So the replica must find out how many transactions it is behind so it can persist the missing
                            transactions on its end and then try to fulfil the operation required on the update state.
                            At this stage as the client isn't byzantine then the received ledger is assumed that it wasn't
                            modified and is the result of the majority of the replicas.
                            */
                            ArrayList<Serialization.Transaction> copyReceivedTransactions = new ArrayList<> (request.ledger.transactions);
                            int end = copyReceivedTransactions.size () - 1;
                            int numberOfTransactionsBehind = getNumberOfTransactionsBehind(copyReceivedTransactions, new ArrayList<> (localSerializableTransactions));
                            int start = end - numberOfTransactionsBehind;
                            log.log(Level.INFO,"This replica contained a ledger that was " + numberOfTransactionsBehind + " transactions behind.");
                            persistMissingTransactions(conn, new ArrayList<> (request.ledger.transactions).subList (start, end), sourceLedger);
                            // continue, to try to perform the operation now on a updated ledger which is agreed by the majority
                        }
                    } else {
                        log.log(Level.INFO,"Local ledger is already in sync with the ledger received");
                    }

                    Ledger targetLedger = Ledger.load(conn, Serialization.base64toPublicKey(request.transaction.target));
                    log.log(Level.INFO, "Load local ledger");
                    // mutual exclusion is necessary to ensure the new transaction ID obtained in "new Transaction"
                    // is still correct/"fresh" when "transaction.persist" is called, and also that the latest
                    // transaction is still the latest transaction
                    synchronized (ledgerLock) {
                        Transaction transaction = new Transaction(conn, sourceLedger, targetLedger, request.transaction.amount,
                                request.transaction.nonce,
                                request.transaction.signature,
                                request.transaction.previousSignature, Transaction.TransactionTypes.SENDING);
                        // checkout the amount from the source ledger
                        sourceLedger.setAmount(sourceLedger.getAmount() - request.transaction.amount);
                        sourceLedger.setTimestamp (request.ledger.timestamp);   //update the timestamp
                        log.log(Level.INFO, "Load local ledger");
                        transaction.persist(conn);
                        log.log(Level.INFO, "Transaction persisted");
                        sourceLedger.persist(conn);
                        log.log(Level.INFO, "ledger persisted");

                        // todo: update the full ledger transactions (before persisting the transaction
                    }
                    conn.commit();
                    response.status = SUCCESS;
                    log.log(Level.INFO, "Transaction created with success.");
                } catch (SQLException e) {
                    // servers fault
                    log.log(Level.SEVERE, "Error related to the database. " + e);
                    response.status = ERROR_SERVER_ERROR;
                }
                // these exceptions are the client's fault
                catch (MissingLedgerException e) {
                    response.status = ERROR_INVALID_LEDGER;
                } catch (InvalidKeyException e) {
                    response.status = ERROR_INVALID_KEY;
                } catch (SignatureException e) {
                    e.printStackTrace ();
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                } finally {
                    if ((response.status == null || !response.status.equals(SUCCESS)) && conn != null) {
                        conn.rollback();
                        log.log(Level.SEVERE, "The transaction created was not persisted, due to an error.");
                    }
                }

                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.status = ERROR_SERVER_ERROR;
                log.log(Level.SEVERE, "Error on processing a send amount request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        post("/receiveAmount", "application/json", (req, res) -> {
            try {
                Serialization.ReceiveAmountRequest request = Serialization.parse(req,
                        Serialization.ReceiveAmountRequest.class);
                log.log(Level.INFO, "Request received at: /receiveAmount \n" +
                        "data on the request:\n" +
                        "SIGNATURE: " + req.headers(Serialization.SIGNATURE_HEADER_NAME) + "\n" +
                        "NONCE: " + request.transaction.nonce + "\n" +
                        "AMOUNT:" + request.transaction.amount + "\n" +
                        "SOURCE PUBLIC KEY: " + request.transaction.source + "\n" +
                        "TARGET PUBLIC KEY: " + request.transaction.target + "\n" +
                        "PENDING TRANSACTION: " + request.pendingTransactionHash);

                Serialization.Response response = new Serialization.Response();
                response.nonce = request.transaction.nonce;

                //Recreate the hash with the data received
                boolean result = Utils.checkSignature(
                        req.headers(Serialization.SIGNATURE_HEADER_NAME),
                        request.getSignable(),
                        request.transaction.source);

                if (!result) {
                    res.status(401);
                    log.log(Level.WARNING, "Mismatch in request signatures");
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                ///////////////////////////////////////////////////
                //We now know that *the whole request* was created by the owner of its respective private key.
                ///////////////////////////////////////////////////

                // now check the transaction itself
                result = Utils.checkSignature(
                        request.transaction.signature,
                        request.transaction.getSignable(),
                        request.transaction.source);

                if (!result) {
                    res.status(401);
                    log.log(Level.WARNING, "Mismatch in transaction signatures");
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                    return prepareResponse(serverPrivateKey, req, res, response);
                }

                Connection conn = null;
                try {
                    conn = Database.getConnection();
                    Ledger sourceLedger = Ledger.load(conn, Serialization.base64toPublicKey(request.transaction.source));

                    // check the timestamp of the request
                    if (sourceLedger.getTimestamp () >= request.ledger.timestamp) {
                        res.status(401);
                        log.log(Level.WARNING, "Older operation");
                        response.status = ERROR_INVALID_LEDGER;
                        return prepareResponse(serverPrivateKey, req, res, response);
                    }

                    //////////////////
                    // verify if the hash of the ledger received match the ledger currently persisted
                    //////////////////

                    // hash the local ledger
                    List<Transaction> localTransactions = sourceLedger.getAllTransactions (conn);
                    List<Serialization.Transaction> localSerializableTransactions = serializeTransactions (localTransactions);
                    VerifiableLedger localLedger = new VerifiableLedger (localSerializableTransactions);
                    String localLedgerHash = Utils.generateHashBase64 (localLedger.getHashable ());

                    // hash the ledger received
                    VerifiableLedger receivedLedger = new VerifiableLedger (request.ledger.transactions);
                    String receivedLedgerHash = Utils.generateHashBase64 (receivedLedger.getHashable ());

                    if (localLedgerHash == null || receivedLedgerHash == null) {
                        res.status(401);
                        log.log(Level.WARNING, "Couldn't hash the transactions.");
                        response.status = ERROR_SERVER_ERROR;   // could be better
                        return prepareResponse(serverPrivateKey, req, res, response);
                    }

                    log.log(Level.INFO, "---------------------------");
                    log.log(Level.INFO, "Ledger received:");
                    log.log(Level.INFO, "timestamp: " + request.ledger.timestamp);
                    log.log(Level.INFO, "signable: " + receivedLedger.getHashable ());
                    log.log(Level.INFO, "Sign: " + receivedLedgerHash);
                    log.log(Level.INFO, "---------------------------");
                    log.log(Level.INFO, "\n");
                    log.log(Level.INFO, "Local ledger: ");
                    log.log(Level.INFO, "timestamp: " + sourceLedger.getTimestamp ());
                    log.log(Level.INFO, "signable: " + localLedger.getHashable ());
                    log.log(Level.INFO, "Sign: " + localLedgerHash);
                    log.log(Level.INFO, "---------------------------");
                    log.log(Level.INFO, "\n");

                    if (!localLedgerHash.equals (receivedLedgerHash)) {
                        int endIndex = localSerializableTransactions.size () - 1;
                        VerifiableLedger subLocalLedger = new VerifiableLedger (localSerializableTransactions.subList (endIndex - 1, endIndex));
                        String subLocalLedgerHash = Utils.generateHashBase64 (subLocalLedger.getHashable ());

                        if (subLocalLedgerHash.equals (receivedLedgerHash)) {
                            Transaction.removeTransaction (conn, localTransactions.get (localTransactions.size () - 1).getId ());
                            conn.commit (); // commit this change
                        } else {
                            ArrayList<Serialization.Transaction> copyReceivedTransactions = new ArrayList<> (request.ledger.transactions);
                            int end = copyReceivedTransactions.size () - 1;
                            int numberOfTransactionsBehind = getNumberOfTransactionsBehind(copyReceivedTransactions, new ArrayList<> (localSerializableTransactions));
                            int start = end - numberOfTransactionsBehind;
                            log.log(Level.INFO,"This replica contained a ledger that was " + numberOfTransactionsBehind + " transactions behind.");
                            persistMissingTransactions(conn, new ArrayList<> (request.ledger.transactions).subList (start, end), sourceLedger);
                        }
                    } else {
                        log.log(Level.INFO,"Local ledger is already in sync with the ledger received");
                    }

                    Ledger targetLedger = Ledger.load(conn, Serialization.base64toPublicKey(request.transaction.target));

                    // mutual exclusion is necessary to ensure the new transaction ID obtained in "new Transaction"
                    // is still correct/"fresh" when "transaction.persist" is called, and also that the latest
                    // transaction is still the latest transaction
                    synchronized (ledgerLock) {
                        Transaction pendingTransaction = Transaction.getTransactionByHash(conn, request.pendingTransactionHash);

                        if (!pendingTransaction.isPending()) {
                            throw new MissingTransactionException("Transaction mentioned in the request is invalid or not pending");
                        }

                        Transaction transaction = new Transaction(conn, sourceLedger, targetLedger,
                                request.transaction.amount,
                                request.transaction.nonce,
                                request.transaction.signature,
                                request.transaction.previousSignature, Transaction.TransactionTypes.RECEIVING);

                        // the Transaction constructor already did some validation, now validate the things that
                        // are specific to RECEIVING transactions
                        if (transaction.getSourceLedger().getId() != pendingTransaction.getTargetLedger().getId() ||
                                transaction.getTargetLedger().getId() != pendingTransaction.getSourceLedger().getId()) {
                            throw new MissingTransactionException("Transaction source/target do not match with pending transaction");
                        }

                        if (transaction.getAmount() != pendingTransaction.getAmount()) {
                            throw new InvalidAmountException("Transaction amount does not match with pending transaction", transaction.getAmount());
                        }
                        // add the amount to the source ledger
                        sourceLedger.setAmount(sourceLedger.getAmount() + request.transaction.amount);
                        sourceLedger.setTimestamp (request.ledger.timestamp);

                        // the sending transaction is not pending anymore
                        pendingTransaction.setPending(false);
                        pendingTransaction.persist(conn);
                        transaction.persist(conn);
                        sourceLedger.persist(conn);
                    }
                    conn.commit();
                    response.status = SUCCESS;
                    log.log(Level.INFO, "Transaction created with success.");
                } catch (SQLException e) {
                    // servers fault
                    log.log(Level.SEVERE, "Error related to the database. " + e);
                    response.status = ERROR_SERVER_ERROR;
                }
                // these exceptions are the client's fault
                catch (MissingLedgerException e) {
                    response.status = ERROR_INVALID_LEDGER;
                } catch (InvalidAmountException e) {
                    response.status = ERROR_INVALID_AMOUNT;
                } catch (MissingTransactionException e) {
                    response.status = ERROR_INVALID_VALUE;
                } catch (InvalidKeyException e) {
                    response.status = ERROR_INVALID_KEY;
                } catch (SignatureException e) {
                    response.status = ERROR_NO_SIGNATURE_MATCH;
                } finally {
                    if ((response.status == null || !response.status.equals(SUCCESS)) && conn != null) {
                        conn.rollback();
                        log.log(Level.SEVERE, "The transaction created was not persisted, due to an error.");
                    }
                }

                return prepareResponse(serverPrivateKey, req, res, response);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.status = ERROR_SERVER_ERROR;
                log.log(Level.SEVERE, "Error on processing a send amount request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        ////////////////////////////////////////////////
        //// READ OPERATIONS
        ////////////////////////////////////////////////

        get("/checkAccount/:key", "application/json", (req, res) -> {
            try {
                // init generic response to use when an error occur
                Serialization.Response errorResponse = new Serialization.Response();
                errorResponse.nonce = req.headers(Serialization.NONCE_HEADER_NAME);
                String pubKeyBase64 = req.params(":key");
                if (pubKeyBase64 == null) {
                    errorResponse.status = ERROR_MISSING_PARAMETER;
                    return prepareResponse(serverPrivateKey, req, res, errorResponse);
                }
                log.log(Level.INFO, "Checking account with public key: " + pubKeyBase64);

                Connection conn = null;
                boolean committed = false;
                try {
                    Serialization.CheckAccountResponse response = new Serialization.CheckAccountResponse();
                    ECPublicKey clientPublicKey = Serialization.base64toPublicKey(pubKeyBase64);
                    conn = Database.getConnection();
                    Ledger ledger = Ledger.load(conn, clientPublicKey);
                    response.nonce = req.headers(Serialization.NONCE_HEADER_NAME);
                    System.out.println("Pending" + ledger.getPendingTransactions(conn, clientPublicKey));
                    response.balance = ledger.getAmount();
                    response.pendingTransactions = serializeTransactions(ledger.getPendingTransactions(conn, clientPublicKey));
                    System.out.println("Balance: " + response.balance);

                    response.status = SUCCESS;
                    log.log(Level.INFO, "Successful check account operation of the ledger with " +
                            "public key: " + pubKeyBase64);
                    conn.commit();
                    committed = true;
                    return prepareResponse(serverPrivateKey, req, res, response);
                } catch (SQLException e) {
                    // servers fault
                    log.log(Level.SEVERE, "Error related to the database. " + e);
                    errorResponse.status = ERROR_SERVER_ERROR;
                }
                // these exceptions are the client's fault
                catch (MissingLedgerException e) {
                    errorResponse.status = ERROR_INVALID_LEDGER;
                } catch (InvalidKeyException e) {
                    errorResponse.status = ERROR_INVALID_KEY;
                } finally {
                    if (conn != null && !committed) {
                        conn.rollback();
                    }
                }
                return prepareResponse(serverPrivateKey, req, res, errorResponse);
            } catch (Exception ex) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.status = ERROR_SERVER_ERROR;
                log.log(Level.SEVERE, "Error on processing a check account request. " + ex);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

        get("/audit/:key", "application/json", (req, res) -> {
            try {
                Serialization.Response errorResponse = new Serialization.Response ();
                errorResponse.nonce = req.headers (Serialization.NONCE_HEADER_NAME);
                String pubKeyBase64 = req.params (":key");
                if (pubKeyBase64 == null) {
                    errorResponse.status = ERROR_MISSING_PARAMETER;
                    return prepareResponse (serverPrivateKey, req, res, errorResponse);
                }
                log.log (Level.INFO, "Going to send audit data for public key: " + pubKeyBase64);

                Connection conn = null;
                try {
                    Serialization.AuditResponse response = new Serialization.AuditResponse ();
                    response.nonce = req.headers (Serialization.NONCE_HEADER_NAME);
                    conn = Database.getConnection ();
                    ECPublicKey publicKey = Serialization.base64toPublicKey (req.params (":key"));
                    Ledger ledger = Ledger.load (conn, publicKey);
                    //response.transactions = serializeTransactions(ledger.getAllTransactions(conn));
                    List<Transaction> transactions = ledger.getAllTransactions (conn);
                    response.ledger = new Serialization.Ledger ();
                    response.ledger.transactions = serializeTransactions (transactions);
                    response.ledger.timestamp = ledger.getTimestamp ();
                    conn.commit ();
                    response.status = SUCCESS;
                    log.log (Level.INFO, "Audit ledger timestamp: " + response.ledger.timestamp + "\n");
                    log.log (Level.INFO, "Audit transactions response: " + response.ledger.transactions + "\n");
                    return prepareResponse (serverPrivateKey, req, res, response);
                } catch (MissingLedgerException e) {
                    errorResponse.status = ERROR_INVALID_LEDGER;
                } catch (InvalidKeyException e) {
                    errorResponse.status = ERROR_INVALID_KEY;
                } catch (SQLException e) {
                    // servers fault
                    log.log (Level.SEVERE, "Error related with the database. " + e);
                    errorResponse.status = ERROR_SERVER_ERROR;
                } finally {
                    if (conn != null) {
                        try {
                            conn.rollback ();
                        } catch (SQLException ex) {
                            // if we can't even rollback, this is now a server error
                            errorResponse.status = ERROR_SERVER_ERROR;
                        }
                    }
                }
                return prepareResponse (serverPrivateKey, req, res, errorResponse);
            }catch (Exception e) {
                res.status(500);
                Serialization.Response response = new Serialization.Response();
                response.status = ERROR_SERVER_ERROR;
                log.log(Level.SEVERE, "Error on processing a check account request. " + e);
                return prepareResponse(serverPrivateKey, req, res, response);
            }
        });

    }

    private static String prepareResponse(ECPrivateKey privateKey, Request sparkRequest, Response sparkResponse, Serialization.Response response) throws JsonProcessingException, SignatureException {

        if (response.statusCode < 0) {
            // try to guess a status code from the status string
            switch (response.status) {
                case SUCCESS:
                    response.statusCode = 200;
                    break;
                case ERROR_SERVER_ERROR:
                    response.statusCode = 500;
                    break;
                default:
                    // all other errors are problems with the request
                    response.statusCode = 400;
            }
        }
        String signature = Utils.generateSignature(response.getSignable(), privateKey);
        sparkResponse.status(response.statusCode);
        sparkResponse.header(Serialization.SIGNATURE_HEADER_NAME, signature);
        sparkResponse.type("application/json");
        return Serialization.serialize(response);
    }

    private static List<ServerInfo> getServersInfoFromKeyStore (URL url, int numberOfServers, String keyStoreFilepath, String serverName) {
        List<ServerInfo> serverInfos = new ArrayList<> ();
        try {
            KeyStore keyStore = Utils.initKeyStore (keyStoreFilepath);
            for (int i = 0; i < numberOfServers; i++) {
                if (serverName.equals (SERVER_PREFIX + i)) {    // don't add it self to the list of replicas
                    continue;
                }
                ServerInfo serverInfo = new ServerInfo ();
                serverInfo.serverUrl = new URL (url.getProtocol () + "://" + url.getHost () + (url.getPort () + i));
                serverInfo.publicKeyBase64 =
                        Serialization.publicKeyToBase64 (Utils.loadPublicKeyFromKeyStore (keyStore, SERVER_PREFIX + (i + 1)));
                serverInfos.add (serverInfo);
            }
            return serverInfos;
        } catch(CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException | KeyException e) {
            e.printStackTrace ();
            throw new RuntimeException (e);
        }
    }

    private static List<Serialization.Transaction> serializeTransactions(List<Transaction> transactions) throws KeyException {
        List<Serialization.Transaction> serializedTransactions = new ArrayList<>();
        for (Transaction tx : transactions) {
            Serialization.Transaction serializedTx = new Serialization.Transaction();
            serializedTx.source = Serialization.publicKeyToBase64(tx.getSourceLedger().getPublicKey());
            serializedTx.target = Serialization.publicKeyToBase64(tx.getTargetLedger().getPublicKey());
            serializedTx.isSend = tx.getTransactionType() == Transaction.TransactionTypes.SENDING;
            serializedTx.amount = tx.getAmount();
            serializedTx.nonce = tx.getNonce();
            serializedTx.previousSignature = tx.getPreviousHash() == null ? "" : tx.getPreviousHash();
            serializedTx.signature = tx.getHash();
            serializedTransactions.add(serializedTx);
        }
        return serializedTransactions;
    }

    private static int getNumberOfTransactionsBehind(List<Serialization.Transaction> copyReceivedTransactions, List<Serialization.Transaction> localSerializableTransactions) {
        String localLedgerHash = Utils.generateHashBase64 (new VerifiableLedger (localSerializableTransactions).getHashable ());
        int maxLength = copyReceivedTransactions.size () - 1;
        for (int i = copyReceivedTransactions.size() - 1; i >= 0; i--) {
            VerifiableLedger receivedLedger = new VerifiableLedger (copyReceivedTransactions);
            String receivedLedgerHash = Utils.generateHashBase64 (receivedLedger.getHashable ());
            if(receivedLedgerHash.equals (localLedgerHash)) {
                return maxLength - i;   // number of transactions behind
            }
        }
        throw new RuntimeException ("Failed to detect the number of transactions behind...");
    }

    private static void persistMissingTransactions(Connection conn, List<Serialization.Transaction> missingTransactions, Ledger sourceLedger)
            throws SQLException, InvalidLedgerException, SignatureException, InvalidAmountException,
            InvalidValueException, KeyException, MissingLedgerException {
        Transaction transaction;
        Ledger targetLedger; // = Ledger.load(conn, Serialization.base64toPublicKey(request.source));
        for (Serialization.Transaction missingTransaction : missingTransactions) {
            targetLedger = Ledger.load (conn, Serialization.base64toPublicKey (missingTransaction.target));
            transaction = new Transaction (conn, sourceLedger, targetLedger, missingTransaction.amount,
                    missingTransaction.nonce, missingTransaction.signature, missingTransaction.previousSignature,
                    missingTransaction.isSend ? Transaction.TransactionTypes.SENDING : Transaction.TransactionTypes.RECEIVING);

            int amount = missingTransaction.isSend ?
                    sourceLedger.getAmount () - missingTransaction.amount : // sending
                    sourceLedger.getAmount () + missingTransaction.amount;  // receiving
            sourceLedger.setAmount (amount);
            synchronized (ledgerLock) {
                transaction.persist (conn);
                sourceLedger.persist (conn);
            }
        }
    }

}
