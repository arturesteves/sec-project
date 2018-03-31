package pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions;


public class CantWritePublicKeyToFileException extends Exception{
    public CantWritePublicKeyToFileException(Throwable exception) {
        super (exception);
    }
}