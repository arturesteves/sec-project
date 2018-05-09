package pt.ulisboa.tecnico.sec.g19.hdscoin.tests;

import org.junit.Before;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.Client;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.AuditException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Serialization;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.Utils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class Helpers {
    private static String keyStoreFilePath = null;

    static {
        String root = Paths.get(System.getProperty("user.dir")).getParent().toString() + "\\common";
        String filepath = root + Serialization.COMMON_PACKAGE_PATH + "\\" + Serialization.KEY_STORE_FILE_NAME;
        keyStoreFilePath = Paths.get(filepath).normalize().toString();
    }

    static String getPreviousHash(Client client, ECPublicKey clientPublicKey) throws AuditException {
        Serialization.AuditResponse transactionsClient1 = client.audit(clientPublicKey);
        return transactionsClient1.ledger.transactions.get(transactionsClient1.ledger.transactions.size() - 1).signature;
    }

    static ECPrivateKey getPrivateKey(String party) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        String password = "abc";
        if (party.startsWith("Server_")) {
            int serverNum = Integer.parseInt(party.substring("Server_".length()));
            password = "ABCD" + Integer.toString(serverNum);
        }

        return Utils.loadPrivateKeyFromKeyStore(getKeyStoreFilePath(), party, password);
    }

    static ECPublicKey getPublicKey(String party) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return Utils.loadPublicKeyFromKeyStore(getKeyStoreFilePath(), party);
    }

    static String getKeyStoreFilePath() {
        return keyStoreFilePath;
    }

    static URL getBaseServerURL() {
        // this URL is just the base URL for the first server, the client increments the port number as needed
        try {
            return new URL("http://localhost:4570");
        } catch (MalformedURLException e) {
            return null;
        }
    }

    static int getNumberOfServers() {
        return 4;
    }
}
