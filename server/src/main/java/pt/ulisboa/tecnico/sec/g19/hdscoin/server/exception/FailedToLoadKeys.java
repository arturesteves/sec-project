package pt.ulisboa.tecnico.sec.g19.hdscoin.server.exception;


public class FailedToLoadKeys extends Exception{

    public FailedToLoadKeys (String message, Throwable t) {
        super (message, t);
    }
}
