package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import com.fasterxml.jackson.core.JsonProcessingException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;


//todo - Add the exception that will be thrown in case of errors
public interface IClient {

    //all these methods can have more arguments in the future, it is not specified in the

    /**
     *  Register the account and associated public key in the system
         before first use. In particular, it should make the necessary initializations to
         enable the first use of the HDS Coins. The account should start with a predefined
         positive balance.
     * @param key The public key to be registered
     */
    void register(ECPrivateKey privateKey, ECPublicKey key, int amount) throws IOException, KeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, UnsupportedEncodingException, SignatureException;

    //todo - Maybe return the current balance for testing purposes
    /**
     *  Submit the request for transferring a given amount from account
         source to account destination, if the balance of the source allows it. If the
         server responds positively to this call, it must be guaranteed that the source
         has the authority to perform the transfer. The transfer will only be finalized
         when the receiver approves it via the receive_amount() method
     * @param privateKey Private key of the client, to sign the transaction
     * @param source Public key of the Source of the transfer
     * @param destination Public key of the Destination of the transfer
     * @param amount The amount to transfer as an integer
     */
    void sendAmount(ECPrivateKey privateKey, ECPublicKey source, ECPublicKey destination, int amount) throws KeyException, IOException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException, SignatureException;


    //todo - Make sure that the return type here is integer
    /**
     *  Obtain the balance of the account associated with key. This
         method also returns the list of pending incoming transfers that require
         approval by the account’s owner, if any.
     * @param key The Public key of the account to be checked
     */
    int checkAccount(ECPrivateKey privateKey, ECPublicKey key);


    /**
     * Used by recipient of a transfer to accept in a non-repudiable way
         a pending incoming transfer that must have been previously authorized by the
         source.
     * @param privateKey Private key of the client, to sign the transaction
     * @param sendTxSignature Signature of the send-transaction we want to receive
     */
    void receiveAmount(ECPrivateKey privateKey, String sendTxSignature) throws KeyException, IOException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException;


    //todo - Discover the return type of the audit operation
    /**
     * Obtain the full transaction history of the account associated with key.
     * @param key The public key of the account to be audited
     */
    void audit(ECPrivateKey privateKey, ECPublicKey key);

}