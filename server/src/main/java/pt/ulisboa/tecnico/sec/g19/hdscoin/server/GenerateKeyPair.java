package pt.ulisboa.tecnico.sec.g19.hdscoin.server;

import org.apache.commons.cli.*;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.exceptions.KeyGenerationException;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;


public class GenerateKeyPair {

    private static KeyStore keyStore;


    public static void main(String[] args)
            throws KeyGenerationException{

        String serverName;
        String password;
        String alias;   // = serverIdentification

        // create options
        Options options = new Options ();
        options.addOption ("n", true, "Name of the server");
        options.addOption ("pw", true, "Password to protect the server key pair");

        CommandLineParser parser = new BasicParser ();
        try {
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("n") && !cmd.getOptionValue("n").trim().equals("")) {
                serverName = cmd.getOptionValue("n");
                alias = serverName;
            } else {
                usage (options);
                throw new KeyGenerationException("Failed to generate a key pair. Missing the -n option.");
            }
            if (cmd.hasOption ("pw") && !cmd.getOptionValue ("pw").trim ().equals ("")) {
                password = cmd.getOptionValue ("pw");
            } else {
                usage (options);
                throw new KeyGenerationException ("Failed to generate a key pair. Missing the -pw option.");
            }

            String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\common";
            String filepath = root + Serialization.COMMON_PACKAGE_PATH + "\\" + Serialization.KEY_STORE_FILE_NAME;
            Path path = Paths.get (filepath).normalize();


            KeyPair keyPair = Utils.generateKeyPair ();

            Certificate certificate = Utils.generateCertificate(keyPair);
            keyStore = Utils.initKeyStore (path.toString ());
            Utils.savePrivateKeyToKeyStore(keyStore, alias, password, (ECPrivateKey) keyPair.getPrivate (), certificate);
            Utils.storeKeyStore(keyStore, path.toString ());

            // everything ok
            System.out.println();
            System.out.println("-------------------------------------");
            System.out.println("---Key Pair Generated with Success---");
            System.out.println("---Key Pair securely saved at a   ---");
            System.out.println("--- keystore located  at:         ---");
            System.out.println(path.toString());
            System.out.println("--- Stored under the alias: " + alias);
            System.out.println("-------------------------------------");

        } catch (ParseException | KeyException | IOException e) {
            e.printStackTrace ();
            throw new KeyGenerationException("Failed to generate a key pair. " + e.getMessage(), e);
        }catch (Exception ex) {
            ex.printStackTrace ();
            throw new KeyGenerationException("Failed to generate a key pair. " + ex.getMessage(), ex);
        }

    }

    private static void usage (Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "GenerateKeyPair", options);
    }




}
