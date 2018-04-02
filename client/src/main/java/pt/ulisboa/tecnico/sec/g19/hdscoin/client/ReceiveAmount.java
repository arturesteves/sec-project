package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.io.IOException;
import java.net.URL;
import java.security.KeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;


public class ReceiveAmount {

    public static final String FILE_PATH = "/src/main/java/pt/ulisboa/tecnico/sec/g19/hdscoin/client/keys";
    public static final String SERVER_URL = "http://localhost:4567";
    public static final String SERVER_PUBLIC_KEY_BASE_64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/GJhA+8icaML6/zYhJ1QY4oEbhzUqjzJmECK5dTJ2mRpS4Vsks0Zy52Q8HiNGQvDpO8wLr/a5X0yTV+Sj1vThQ==";

    public static void main (String[] args) throws CantReceiveAmountException {
        String clientNameSource;
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
            throw new CantReceiveAmountException ("Can't receive amount, because arguments are missing. " + e);
        }

        if (cmd.hasOption ("n")) {
            clientNameSource = cmd.getOptionValue ("n");
        } else {
            usage (registerOptions);
            throw new CantReceiveAmountException ("Can't receive amount, the name of the client is missing.");
        }
        if (cmd.hasOption ("ts")) {
            transactionSignature = cmd.getOptionValue ("ts");
        } else {
            usage (registerOptions);
            throw new CantReceiveAmountException ("Can't receive amount, the transaction signature is missing.");
        }

        String fileNameSource = FILE_PATH + "/" + clientNameSource + ".keys";


        try {
            ECPublicKey sourcePublickey = Utils.readPublicKeyFromFile (fileNameSource);
            ECPrivateKey sourcePrivateKey = Utils.readPrivateKeyFromFile (fileNameSource);
            ECPublicKey serverPublicKey = Serialization.base64toPublicKey (SERVER_PUBLIC_KEY_BASE_64);

            IClient client = new Client (new URL(SERVER_URL), serverPublicKey);
            client.receiveAmount (sourcePublickey, sourcePrivateKey, transactionSignature);

        } catch (KeyException | IOException e) {
            throw new CantReceiveAmountException ("Failed to receive amount. " + e);
        }

    }

    private static void usage (Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "Register", options);
    }

}
