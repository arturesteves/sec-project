package pt.ulisboa.tecnico.sec.g19.hdscoin.client;

import pt.ulisboa.tecnico.sec.g19.hdscoin.client.exceptions.*;

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
     * @throws CantRegisterException If there are any problems while trying to register a public key.
     */
    void register(ECPublicKey publicKey, ECPrivateKey privateKey, double amount) throws CantRegisterException;

    /**
     * Submit the request for transferring a given amount from account
     * source to account destination, if the balance of the source allows it.
     * The transfer will only be finalized when the receiver approves it via the receiveAmount() method.
     *
     * @param sourcePublicKey   Public key of the client that is sending the transaction.
     * @param targetPublicKey   Public key of the client that is receiving the transaction.
     * @param amount            Amount to transfer.
     * @param sourcePrivateKey  Private key of the client that is sending the transaction, used to sign the message.
     * @param previousSignature Signature of the last transaction.
     * @throws CantSendAmountException If there are any problems while trying to create a transaction.
     */
    void sendAmount(ECPublicKey sourcePublicKey, ECPublicKey targetPublicKey, double amount,
                    ECPrivateKey sourcePrivateKey, String previousSignature) throws CantSendAmountException;

    /**
     * Obtain the balance of the account associated with key.

     * @param publicKey Public key of the client
     *
     * @return int -
     */
    int checkAccount(ECPublicKey publicKey) throws CantCheckAccountException;

    /**
     * Used by recipient of a transfer to accept in a non-repudiable way
     * a pending incoming transfer that was previously authorized by the
     * source.
     *
     * @param publicKey            Public key of the client.
     * @param privateKey           Private key of the client, used to sign the message.
     * @param transactionSignature Signature of the transaction to receive the amount.
     * @throws CantReceiveAmountException If there are any problems while trying to complete a transaction.
     */
    void receiveAmount (ECPublicKey publicKey, ECPrivateKey privateKey, String transactionSignature) throws CantReceiveAmountException;

    //TODO: check
    //todo - Discover the return type of the audit operation
    /**
     * Obtain the full transaction history of the account associated with key.
     * @param key The public key of the account to be audited
     */
    void audit(ECPrivateKey privateKey, ECPublicKey key);

}