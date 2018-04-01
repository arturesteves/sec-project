package pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions;


public class CantGenerateSignatureException extends Exception{
    public CantGenerateSignatureException (String message, Throwable t) {
        super (message, t);
    }
}
