package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.SendAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.AuditException;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;


public class SendAmount {

    public static final String SERVER_URL = "http://localhost:4567";

    public static void main(String[] args) throws SendAmountException {
        String clientNameSource;
        String clientNameTarget;
        String serverName;
        int amount;

        // create options
        Options registerOptions = new Options();
        registerOptions.addOption("ns", true, "The name of the client that is sending the amount.");
        registerOptions.addOption("nt", true, "The name of the client that is receiving.");
        registerOptions.addOption("s", true, "Server name");
        registerOptions.addOption("a", true, "Amount to send.");

        CommandLineParser parser = new BasicParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(registerOptions, args);
        } catch (ParseException e) {
            throw new SendAmountException("Can't send amount, because arguments are missing. " + e);
        }

        if (cmd.hasOption("ns") && !cmd.getOptionValue("ns").trim().equals("")) {
            clientNameSource = cmd.getOptionValue("ns");
        } else {
            usage(registerOptions);
            throw new SendAmountException("Can't send amount, the name of the source client is missing.");
        }
        if (cmd.hasOption("nt") && !cmd.getOptionValue("nt").trim().equals("")) {
            clientNameTarget = cmd.getOptionValue("nt");
        } else {
            usage(registerOptions);
            throw new SendAmountException("Can't send amount, the name of the target client is missing.");
        }
        if (cmd.hasOption("s") && !cmd.getOptionValue("s").trim().equals("")) {
            serverName = cmd.getOptionValue("s");
        } else {
            usage(registerOptions);
            throw new SendAmountException("Can't send amount, server name is missing.");
        }
        if (cmd.hasOption("a") && !cmd.getOptionValue("a").trim().equals("")) {
            try {
                amount = Integer.parseInt(cmd.getOptionValue("a"));
            } catch (NullPointerException | NumberFormatException e) {
                throw new SendAmountException("Can't send amount, the amount is invalid. " + e);
            }
        } else {
            usage(registerOptions);
            throw new SendAmountException("Can't send amount, the amount is missing.");
        }

        String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\client";
        String filepathSource = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\" + clientNameSource + ".keys";
        String filepathTarget = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\" + clientNameTarget + ".keys";
        Path pathSource = Paths.get(filepathSource).normalize(); // create path and normalize it
        Path pathTarget = Paths.get(filepathTarget).normalize();
        String serverKeyFilepath = root + "\\..\\server\\" + Serialization.SERVER_PACKAGE_PATH + "\\keys\\" + serverName + ".keys";
        Path serverKeyPath = Paths.get(serverKeyFilepath).normalize(); // create path and normalize it

        try {
            ECPublicKey sourcePublickey = Utils.readPublicKeyFromFile(pathSource.toString());
            ECPrivateKey sourcePrivateKey = Utils.readPrivateKeyFromFile(pathSource.toString());
            ECPublicKey targetPublicKey = Utils.readPublicKeyFromFile(pathTarget.toString());
            ECPublicKey serverPublicKey = Utils.readPublicKeyFromFile(serverKeyPath.toString());

            IClient client = new Client(new URL(SERVER_URL), serverPublicKey);
            // get the hash of our last transaction, so we can include it in the new transaction
            // client.audit verifies the transaction chain for us
            List<Serialization.Transaction> transactions = client.audit(sourcePublickey);
            // transactions.size() should always be > 0 because of the dummy transaction required to open an account
            if(transactions.size() == 0) {
                throw new SendAmountException("Ledger has too few transactions (account appears to not have been initialized on the server)");
            }
            String previousSignature = transactions.get(transactions.size() - 1).signature;
            client.sendAmount(sourcePublickey, targetPublicKey, amount, sourcePrivateKey, previousSignature);

        } catch (KeyException | IOException e) {
            throw new SendAmountException("Failed to create a transaction. " + e);
        } catch (AuditException e) {
            throw new SendAmountException("Self-auditing failed. " + e);
        }

    }

    private static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("SendAmount", options);
    }

}
