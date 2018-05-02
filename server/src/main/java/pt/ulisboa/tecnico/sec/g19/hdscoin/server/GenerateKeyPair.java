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
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;


public class GenerateKeyPair {

    private static KeyStore keyStore;



    public static void main(String[] args)
            throws KeyGenerationException{
        // distinguir keystore pw da alias pw
        String serverName;
        String password;
        String alias;   // = serverIdentification
        String keyPassword; // serverIdentification + password

        // create options
        Options options = new Options ();
        options.addOption ("n", true, "Name of the server");
        options.addOption ("pw", true, "Keystore password");

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
            // create path and normalize it
            //String filepath = root + Serialization.COMMON_PACKAGE_PATH + "\\keys\\" + serverName + ".keys";
            //Path path = Paths.get (filepath).normalize();

            KeyPair keyPair = Utils.generateKeyPair ();
            //Utils.writeKeyPairToFile (path.toString(), keyPair);

            // everything ok
            System.out.println();
            System.out.println("-------------------------------------");
            System.out.println("---Key Pair Generated with Success---");
            System.out.println("---Key Pair securely saved at a   ---");
            System.out.println("--- keystore located  at:         ---");
            System.out.println(path.toString());
            System.out.println("-------------------------------------");

            Certificate certificate = Utils.generateCertificate(keyPair);
            keyStore = Utils.initKeyStore (path.toString ());
            Utils.savePrivateKeyToKeyStore(keyStore, alias, password, (ECPrivateKey) keyPair.getPrivate (), certificate);
            Utils.storeKeyStore(keyStore, path.toString ());
            ECPrivateKey privateKey = Utils.loadPrivateKeyFromKeyStore(path.toString (), alias, password);
            ECPublicKey publicKey = Utils.loadPublicKeyFromKeyStore(keyStore, alias);

            System.out.println ("Private key generated: " + Serialization.privateKeyToBase64 ((ECPrivateKey) keyPair.getPrivate ()));
            System.out.println ("Public key generated: " + Serialization.publicKeyToBase64 ((ECPublicKey) keyPair.getPublic ()));
            System.out.println ("Private key fetched: " + Serialization.privateKeyToBase64 (privateKey));
            System.out.println ("Public key fetched: " + Serialization.publicKeyToBase64 (publicKey));
            System.out.println ("Server name: " + serverName);
            System.out.println ("password: " + password);
            System.out.println ("alias: " + alias);

            if(serverName.equals ("Server_2")) {
                ECPublicKey publicKey2 = Utils.loadPublicKeyFromKeyStore(keyStore, "Server_1");
                System.out.println ("Public key from Server_1 fetched: " + Serialization.publicKeyToBase64 (publicKey2));
            }
            System.out.println ("\n END");
        } catch (ParseException | KeyException | IOException e) {
            throw new KeyGenerationException("Failed to generate a key pair. " + e.getMessage(), e);
        }catch (Exception ex) {
            ex.printStackTrace ();
        }

    }

    private static void usage (Options options) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "GenerateKeyPair", options);
    }




}
