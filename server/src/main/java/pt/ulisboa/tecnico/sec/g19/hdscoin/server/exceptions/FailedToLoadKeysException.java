package pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions;


public class FailedToLoadKeysException extends Exception{

    public FailedToLoadKeysException(String message, Throwable t) {
        super (message, t);
    }
}
