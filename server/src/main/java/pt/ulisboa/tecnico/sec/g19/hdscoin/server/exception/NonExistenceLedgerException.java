package pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception;

import java.security.interfaces.ECPublicKey;

public class NonExistenceLedgerException extends Exception {

    public NonExistenceLedgerException (String message, ECPublicKey key) {
        super (message + " Key: " + key);
    }
}
