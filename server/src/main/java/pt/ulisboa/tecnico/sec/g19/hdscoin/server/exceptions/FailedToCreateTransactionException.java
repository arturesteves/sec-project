package pt.ulisboa.tecnico.sec.g19.hdscoin.server.exceptions;


public class FailedToCreateTransactionException extends Exception{
    public FailedToCreateTransactionException (String message, Throwable t){
        super (message, t);
    }
}
