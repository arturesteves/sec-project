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


public class ReceiveAmount {

    public static final String SERVER_URL = "http://localhost:4567";
    public static final String SERVER_PUBLIC_KEY_BASE_64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/GJhA+8icaML6/zYhJ1QY4oEbhzUqjzJmECK5dTJ2mRpS4Vsks0Zy52Q8HiNGQvDpO8wLr/a5X0yTV+Sj1vThQ==";

    public static void main (String[] args) throws ReceiveAmountException {
        String clientName;
        String transactionSignature;

        // create options
        Options registerOptions = new Options ();
        registerOptions.addOption ("n", true, "The name of the client name that is receiving.");
        registerOptions.addOption ("ts", true, "Signature of the transaction to receive the amount.");

        CommandLineParser parser = new BasicParser ();
        CommandLine cmd = null;

        try {
            cmd = parser.parse (registerOptions, args);
        } catch (ParseException e) {
            throw new ReceiveAmountException("Can't receive amount, because arguments are missing. " + e);
        }

        if (cmd.hasOption ("n") && !cmd.getOptionValue("n").trim().equals("")) {
            clientName = cmd.getOptionValue ("n");
        } else {
            usage (registerOptions);
            throw new ReceiveAmountException("Can't receive amount, the name of the client is missing.");
        }
        if (cmd.hasOption ("ts") && !cmd.getOptionValue("ts").trim().equals("")) {
            transactionSignature = cmd.getOptionValue ("ts");
        } else {
            usage (registerOptions);
            throw new ReceiveAmountException("Can't receive amount, the transaction signature is missing.");
        }

        String root = System.getProperty("user.dir");
        String filepath = root + Serialization.CLIENT_PACKAGE_PATH + "\\keys\\" + clientName + ".keys";
        Path path = Paths.get (filepath).normalize(); // create path and normalize it

        try {
            ECPublicKey sourcePublickey = Utils.readPublicKeyFromFile (path.toString());
            ECPrivateKey sourcePrivateKey = Utils.readPrivateKeyFromFile (path.toString());
            ECPublicKey serverPublicKey = Serialization.base64toPublicKey (SERVER_PUBLIC_KEY_BASE_64);

            IClient client = new Client (new URL(SERVER_URL), serverPublicKey);
            client.receiveAmount (sourcePublickey, sourcePrivateKey, transactionSignature);

        } catch (KeyException | IOException e) {
            throw new ReceiveAmountException("Failed to receive amount. " + e);
        }

    }

    private static void usage (Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "Register", options);
    }

}
