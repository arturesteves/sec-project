package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CantRegisterException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.InvalidClientSignatureException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import java.io.IOException;
import java.net.URL;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class Register {

    public static final String FILE_PATH = "/src/main/java/pt/ulisboa/tecnico/sec/g19/hdscoin/client/keys";
    public static final String SERVER_URL = "http://localhost:4567";
    public static final String SERVER_PUBLIC_KEY_BASE_64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/GJhA+8icaML6/zYhJ1QY4oEbhzUqjzJmECK5dTJ2mRpS4Vsks0Zy52Q8HiNGQvDpO8wLr/a5X0yTV+Sj1vThQ==";

    public static void main (String[] args) throws CantRegisterException, InvalidClientSignatureException {
        String fileName;
        String clientName;
        double amount = -1.0;

        // create options
        Options registerOptions = new Options ();
        registerOptions.addOption ("n", true, "Client name");
        registerOptions.addOption ("a", true, "Amount to initialize the account");

        CommandLineParser parser = new BasicParser ();
        CommandLine cmd = null;

        try {
            cmd = parser.parse (registerOptions, args);
        } catch (ParseException e) {
            e.printStackTrace();
            throw new CantRegisterException("Can't register, because arguments are missing. " + e.getMessage(), e);
        }

        if (cmd.hasOption ("n")) {
            clientName = cmd.getOptionValue ("n");
        } else {
            usage (registerOptions);
            throw new RuntimeException ("Missing the -n option.");
        }
        if (cmd.hasOption ("a")) {
            try {
                amount = Double.parseDouble (cmd.getOptionValue ("a"));
            } catch (NullPointerException | NumberFormatException e) {
                System.out.println(e.getMessage());
            }
        } else {
            usage (registerOptions);
            throw new RuntimeException ("Missing the -a option.");
        }

        fileName = FILE_PATH + "/" + clientName + ".keys";

        try {
            ECPublicKey clientPublickey = Utils.readPublicKeyFromFile (fileName);
            ECPrivateKey clientPrivateKey = Utils.readPrivateKeyFromFile (fileName);
            ECPublicKey serverPublicKey = Serialization.base64toPublicKey (SERVER_PUBLIC_KEY_BASE_64);

            IClient client = new Client(new URL(SERVER_URL), serverPublicKey);
            client.register(clientPrivateKey, clientPublickey, amount);

        } catch (KeyException | IOException e) {
            throw new CantRegisterException("Unable to register. " + e.getMessage(), e);
        }

    }

    private static void usage (Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "Register", options);
    }

}