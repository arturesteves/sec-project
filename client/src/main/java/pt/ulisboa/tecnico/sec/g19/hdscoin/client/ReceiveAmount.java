package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;


public class ReceiveAmount {

    public static final String SERVER_URL = "http://localhost:4570";

    public static void main(String[] args) throws ReceiveAmountException {
        String clientName;
        String serverName;
        String transactionSignature;

        // create options
        Options registerOptions = new Options();
        registerOptions.addOption("n", true, "The name of the client name that is receiving.");
        registerOptions.addOption("ts", true, "Signature of the transaction to receive the amount.");
        registerOptions.addOption("s", true, "Server name");

        CommandLineParser parser = new BasicParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(registerOptions, args);
        } catch (ParseException e) {
            throw new ReceiveAmountException("Can't receive amount, because arguments are missing. " + e);
        }

        if (cmd.hasOption("n") && !cmd.getOptionValue("n").trim().equals("")) {
            clientName = cmd.getOptionValue("n");
        } else {
            usage(registerOptions);
            throw new ReceiveAmountException("Can't receive amount, the name of the client is missing.");
        }
        if (cmd.hasOption("ts") && !cmd.getOptionValue("ts").trim().equals("")) {
            transactionSignature = cmd.getOptionValue("ts");
        } else {
            usage(registerOptions);
            throw new ReceiveAmountException("Can't receive amount, the transaction signature is missing.");
        }
        if (cmd.hasOption("s") && !cmd.getOptionValue("s").trim().equals("")) {
            serverName = cmd.getOptionValue("s");
        } else {
            usage(registerOptions);
            throw new ReceiveAmountException("Can't check account, server name is missing.");
        }

        String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\client";
        String filepath = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\" + clientName + ".keys";
        Path path = Paths.get(filepath).normalize(); // create path and normalize it
        String serverKeyFilepath = root + "\\..\\server\\" + Serialization.SERVER_PACKAGE_PATH + "\\keys\\" + serverName + ".keys";
        Path serverKeyPath = Paths.get(serverKeyFilepath).normalize(); // create path and normalize it

        try {
            ECPublicKey sourcePublickey = Utils.readPublicKeyFromFile(path.toString());
            ECPrivateKey sourcePrivateKey = Utils.readPrivateKeyFromFile(path.toString());
            ECPublicKey serverPublicKey = Utils.readPublicKeyFromFile(serverKeyPath.toString());

            IClient client = new Client(new URL(SERVER_URL), serverPublicKey);

            // check account to get pending incoming transactions
            Serialization.Transaction pendingTx = null;
            CheckAccountResult result = client.checkAccount(sourcePublickey);
            for (Serialization.Transaction tx : result.pendingTransactions) {
                if (tx.signature.equals(transactionSignature)) {
                    pendingTx = tx;
                }
            }

            if (pendingTx == null) {
                throw new ReceiveAmountException("A pending transaction with the specified signature was not found");
            }

            // get the hash of our last transaction, so we can include it in the new transaction
            // client.audit verifies the transaction chain for us
            List<Serialization.Transaction> transactions = client.audit(sourcePublickey);
            // transactions.size() should always be > 0 because of the dummy transaction required to open an account
            if (transactions.size() == 0) {
                throw new ReceiveAmountException("Ledger has too few transactions (account appears to not have been initialized on the server)");
            }
            String previousSignature = transactions.get(transactions.size() - 1).signature;

            // pendingTx.source is the target of the receiving transaction
            client.receiveAmount(sourcePublickey, pendingTx.source, pendingTx.amount, sourcePrivateKey, previousSignature, transactionSignature);

        } catch (AuditException e) {
            throw new ReceiveAmountException("Failed to audit ledger. " + e);
        } catch (KeyException | IOException | CheckAccountException e) {
            throw new ReceiveAmountException("Failed to receive amount. " + e);
        }

    }

    private static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("ReceiveAmount", options);
    }

}
