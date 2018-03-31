package pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions;


public class CantGenerateKeysException extends Exception{
    public CantGenerateKeysException(Throwable exception) {
        super (exception);
    }
}