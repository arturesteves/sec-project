package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CantCheckAccountException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.CantRegisterException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.InvalidClientSignatureException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.InvalidServerResponseException;
import pt.ulisboa.tecnico.sec.g19.hdscoin.common.execeptions.CantGenerateSignatureException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public interface IClient {

    /**
     * Register the account and associated public key in the system before first use.
     * Initialize the proper structures to enable the use of the HDS coins.
     *
     * @param publicKey     public key of the client
     * @param privateKey    private key of the client, used to sign the message
     * @param amount        initial amount
     * @throws CantRegisterException If the operation isn't successful due to an invalid argument,
     *                               or the server couldn't verify who sign it, or the client couldn't verify
     *                               if the server sign it, or occurred a server error.
     */
    void register(ECPublicKey publicKey, ECPrivateKey privateKey, double amount) throws CantRegisterException;

    //TODO: check
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
    void sendAmount(ECPrivateKey privateKey, ECPublicKey source, ECPublicKey destination, double amount) throws KeyException, IOException, CantGenerateSignatureException, InvalidServerResponseException, InvalidClientSignatureException;


    //todo - Make sure that the return type here is integer
    /**
     *  Obtain the balance of the account associated with key. This
         method also returns the list of pending incoming transfers that require
         approval by the account’s owner, if any.
     * @param key The Public key of the account to be checked
     */

    /**
     * Obtain the balance of the account associated with key.

     * @param publicKey Public key of the client
     *
     * @return
     */
    int checkAccount(ECPublicKey publicKey) throws CantCheckAccountException;


    //TODO: check
    /**
     * Used by recipient of a transfer to accept in a non-repudiable way
         a pending incoming transfer that must have been previously authorized by the
         source.
     * @param privateKey Private key of the client, to sign the transaction
     * @param sendTxSignature Signature of the send-transaction we want to receive
     */
    void receiveAmount(ECPrivateKey privateKey, String sendTxSignature) throws KeyException, IOException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException;

    //TODO: check
    //todo - Discover the return type of the audit operation
    /**
     * Obtain the full transaction history of the account associated with key.
     * @param key The public key of the account to be audited
     */
    void audit(ECPrivateKey privateKey, ECPublicKey key);

}