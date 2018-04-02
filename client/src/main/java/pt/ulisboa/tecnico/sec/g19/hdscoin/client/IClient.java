package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.*;
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
     * @param publicKey     Public key of the client.
     * @param privateKey    Private key of the client, used to sign the message.
     * @param amount        Initial amount.
     * @throws CantRegisterException If the operation isn't successful due to an invalid argument,
     *                               or the server couldn't verify who sign it, or the client couldn't verify
     *                               if the server sign it, or occurred a server error.
     */
    void register(ECPublicKey publicKey, ECPrivateKey privateKey, double amount) throws CantRegisterException;

    /**
     * Submit the request for transferring a given amount from account
     * source to account destination, if the balance of the source allows it.
     *
     * @param sourcePublicKey   Public key of the client that is sending the transaction.
     * @param targetPublicKey   Public key of the client that is receiving the transaction.
     * @param amount            Amount to transfer.
     * @param sourcePrivateKey  Private key of the client that is sending the transaction, used to sign the message.
     * @param previousSignature Signature of the last transaction.
     * @throws CantSendAccountException If the operation isn't successful due to an invalid argument,
     *                               or the server couldn't verify who sign it, or the client couldn't verify
     *                               if the server sign it, or occurred a server error.
     */
    void sendAmount(ECPublicKey sourcePublicKey, ECPublicKey targetPublicKey, double amount,
                    ECPrivateKey sourcePrivateKey, String previousSignature) throws CantSendAccountException;

    /**
     * Obtain the balance of the account associated with key.

     * @param publicKey Public key of the client
     *
     * @return int -
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