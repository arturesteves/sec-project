package pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions;


public class FailedToLoadKeys extends Exception{

    public FailedToLoadKeys (String message, Throwable t) {
        super (message, t);
    }
}
