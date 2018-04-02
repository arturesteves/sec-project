package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CantCheckAccountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CantRegisterException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CantSendAccountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.InvalidClientSignatureException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.io.IOException;
import java.net.URL;
import java.security.KeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;


public class SendAmount {

    public static final String FILE_PATH = "/src/main/java/pt/ulisboa/tecnico/sec/g19/hdscoin/client/keys";
    public static final String SERVER_URL = "http://localhost:4567";
    public static final String SERVER_PUBLIC_KEY_BASE_64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/GJhA+8icaML6/zYhJ1QY4oEbhzUqjzJmECK5dTJ2mRpS4Vsks0Zy52Q8HiNGQvDpO8wLr/a5X0yTV+Sj1vThQ==";

    public static void main (String[] args) throws CantSendAccountException {
        String clientNameSource;
        String clientNameTarget;
        double amount;

        // create options
        Options registerOptions = new Options ();
        registerOptions.addOption ("ns", true, "The name of the client that is sending the amount.");
        registerOptions.addOption ("nt", true, "The name of the client that is receiving.");
        registerOptions.addOption ("a", true, "Amount to send.");

        CommandLineParser parser = new BasicParser ();
        CommandLine cmd = null;

        try {
            cmd = parser.parse (registerOptions, args);
        } catch (ParseException e) {
            throw new CantSendAccountException ("Can't send amount, because arguments are missing. " + e);
        }

        if (cmd.hasOption ("ns")) {
            clientNameSource = cmd.getOptionValue ("ns");
        } else {
            usage (registerOptions);
            throw new CantSendAccountException ("Can't send amount, the name of the source client is missing.");
        }
        if (cmd.hasOption ("nt")) {
            clientNameTarget = cmd.getOptionValue ("nt");
        } else {
            usage (registerOptions);
            throw new CantSendAccountException ("Can't send amount, the name of the target client is missing.");
        }
        if (cmd.hasOption ("a")) {
            try {
                amount = Double.parseDouble (cmd.getOptionValue ("a"));
            } catch (NullPointerException | NumberFormatException e) {
                throw new CantSendAccountException ("Can't send amount, the amount is invalid. " + e);
            }
        } else {
            usage (registerOptions);
            throw new CantSendAccountException ("Can't send amount, the amount is missing.");
        }

        String fileNameSource = FILE_PATH + "/" + clientNameSource + ".keys";
        String fileNameTarget = FILE_PATH + "/" + clientNameTarget + ".keys";


        try {
            ECPublicKey sourcePublickey = Utils.readPublicKeyFromFile (fileNameSource);
            ECPrivateKey sourcePrivateKey = Utils.readPrivateKeyFromFile (fileNameSource);
            ECPublicKey targetPublicKey = Utils.readPublicKeyFromFile (fileNameTarget);
            ECPublicKey serverPublicKey = Serialization.base64toPublicKey (SERVER_PUBLIC_KEY_BASE_64);

            // todo: first we have to audit the account to retrieve the last transaction.
            String previousHash = "";
            IClient client = new Client (new URL(SERVER_URL), serverPublicKey);
            client.sendAmount (sourcePublickey, targetPublicKey, amount, sourcePrivateKey, previousHash);

        } catch (KeyException | IOException e) {
            throw new CantSendAccountException ("Failed to create a transaction. " + e);
        }

    }

    private static void usage (Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "Register", options);
    }

}
