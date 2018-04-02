package pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions;


public class CantGenerateKeysException extends Exception{
    public CantGenerateKeysException(String message, Throwable t) {
        super (message, t);
    }

    public CantGenerateKeysException(String message) {
        super(message);
    }
}