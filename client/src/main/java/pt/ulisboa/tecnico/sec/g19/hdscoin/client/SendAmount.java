package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CantSendAmountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;


public class SendAmount {

    public static final String SERVER_URL = "http://localhost:4567";
    public static final String SERVER_PUBLIC_KEY_BASE_64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/GJhA+8icaML6/zYhJ1QY4oEbhzUqjzJmECK5dTJ2mRpS4Vsks0Zy52Q8HiNGQvDpO8wLr/a5X0yTV+Sj1vThQ==";

    public static void main(String[] args) throws CantSendAmountException {
        String clientNameSource;
        String clientNameTarget;
        int amount;

        // create options
        Options registerOptions = new Options();
        registerOptions.addOption("ns", true, "The name of the client that is sending the amount.");
        registerOptions.addOption("nt", true, "The name of the client that is receiving.");
        registerOptions.addOption("a", true, "Amount to send.");

        CommandLineParser parser = new BasicParser();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(registerOptions, args);
        } catch (ParseException e) {
            throw new CantSendAmountException("Can't send amount, because arguments are missing. " + e);
        }

        if (cmd.hasOption("ns") && !cmd.getOptionValue("ns").trim().equals("")) {
            clientNameSource = cmd.getOptionValue("ns");
        } else {
            usage(registerOptions);
            throw new CantSendAmountException("Can't send amount, the name of the source client is missing.");
        }
        if (cmd.hasOption("nt") && !cmd.getOptionValue("nt").trim().equals("")) {
            clientNameTarget = cmd.getOptionValue("nt");
        } else {
            usage(registerOptions);
            throw new CantSendAmountException("Can't send amount, the name of the target client is missing.");
        }
        if (cmd.hasOption("a") && !cmd.getOptionValue("a").trim().equals("")) {
            try {
                amount = Integer.parseInt(cmd.getOptionValue("a"));
            } catch (NullPointerException | NumberFormatException e) {
                throw new CantSendAmountException("Can't send amount, the amount is invalid. " + e);
            }
        } else {
            usage(registerOptions);
            throw new CantSendAmountException("Can't send amount, the amount is missing.");
        }

        String root = System.getProperty("user.dir");
        String filepathSource = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\" + clientNameSource + ".keys";
        String filepathTarget = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\" + clientNameTarget + ".keys";
        Path pathSource = Paths.get(filepathSource).normalize(); // create path and normalize it
        Path pathTarget = Paths.get(filepathTarget).normalize();

        try {
            ECPublicKey sourcePublickey = Utils.readPublicKeyFromFile(pathSource.toString());
            ECPrivateKey sourcePrivateKey = Utils.readPrivateKeyFromFile(pathSource.toString());
            ECPublicKey targetPublicKey = Utils.readPublicKeyFromFile(pathTarget.toString());
            ECPublicKey serverPublicKey = Serialization.base64toPublicKey(SERVER_PUBLIC_KEY_BASE_64);

            // todo: first we have to audit the account to retrieve the last transaction.
            String previousHash = "";
            IClient client = new Client(new URL(SERVER_URL), serverPublicKey);
            client.sendAmount(sourcePublickey, targetPublicKey, amount, sourcePrivateKey, previousHash);

        } catch (KeyException | IOException e) {
            throw new CantSendAmountException("Failed to create a transaction. " + e);
        }

    }

    private static void usage(Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("SendAmount", options);
    }

}
