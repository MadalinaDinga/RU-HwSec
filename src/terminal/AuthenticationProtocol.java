/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package terminal;

import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import common.Constants;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import org.apache.commons.lang3.ArrayUtils;

/**
 *
 * @author tom
 */
public class AuthenticationProtocol extends Protocol {

    private final byte[] terminalKeyCertificate;
    private final RSAPublicKey masterVerifyKey;
    private final RSAPrivateKey terminalPrivateKey;
    private final RSAPublicKey terminalPublicKey;
    public RSAPublicKey cardVerifyKey;
    public RSAPublicKey cardEncryptionKey;
 
    public AuthenticationProtocol(
            RSAPublicKey terminalPubKey,
            RSAPrivateKey terminalPrivateKey,
            RSAPublicKey masterVerifyKey,
            byte[] terminalKeyCertificate) {
        this.terminalPublicKey = terminalPubKey;
        this.terminalPrivateKey = terminalPrivateKey;
        this.masterVerifyKey = masterVerifyKey;
        this.terminalKeyCertificate = terminalKeyCertificate;
    }
    
    /**
     * Runs the authentication protocol and sets the fields cardVerifyKey, cardEncryptionKey
     * @return True if successfully authenticated with card, false otherwise.
     */
    public boolean run(CardChannel applet) {
        ResponseAPDU rapdu;
        byte[] cardModulus, cardExponent, cardCertificate;
        
        try {
            // Indicate start of the protocol to the card
            rapdu = sendCommand(applet, startAuthenticationProtocol(), 0x9000, "Start authentication message returned SW: ");
            
            // Exchange moduli with the card
            rapdu = sendCommand(applet, modulus(), 0x9000, "Exchanging the modulus resulted in SW: ");
            cardModulus = rapdu.getData();
            
            // Exchange exponents with the card
            rapdu = sendCommand(applet, exponent(), 0x9000, "Exchanging the exponent resulted in SW: ");
            cardExponent = rapdu.getData();
            
            // Exchange certificates with the card
            rapdu = sendCommand(applet, certificate(), 0x9000, "Exchanging the certificate resulted in SW: ");
            
            cardCertificate = rapdu.getData();
            
            if (!verifyKeyCertificate(cardModulus, cardExponent, cardCertificate, masterVerifyKey)) {
            
                System.out.println("Signature of card is invalid.");
                return false;
            }
            
            cardVerifyKey = buildCardKeys(cardModulus, cardExponent);
            
            // Challenge the card
            byte[] nonce = new byte[Constants.CHALLENGE_LENGTH];   
            SecureRandom random = new SecureRandom();
            random.nextBytes(nonce);         
            
            rapdu = sendCommand(applet, challenge(nonce), 0x9000, "Sending challenge to card resulted in SW: ");
            byte[] challengeResponse = rapdu.getData();
            
            if (!verifyChallengeResponse(Constants.CHALLENGE_TAG, nonce, challengeResponse, cardVerifyKey)) {
                System.err.println("Card failed to repond to the challenge");
                return false;
            }
            
            // Get challenged by the card
            rapdu = sendCommand(applet, readyForChallenge(), 0x9000, "Requesting challenge from card resulted in SW: ");
            byte[] challenge = rapdu.getData();
            
            if (!isWellFormattedChallenge(challenge)) {
                System.err.println("Received challenge is illformated.");
                return false;
            }
            
            byte[] response = signChallenge(challenge, terminalPrivateKey);
            
            // Respond to the challenge received by the card
            rapdu = sendCommand(applet, respondToChallenge(response), 0x9000, "Response to challenge of card resulted in SW: ");
            byte[] encryptionKeyCertificate = rapdu.getData();
            
            // Let the card send its modulus
            rapdu = sendCommand(applet, empty(), 0x9000, "Request for enc modulus resulted in SW: ");
            byte[] encryptionKeyModulus = rapdu.getData();
            
            // Let the card send its exponent
            rapdu = sendCommand(applet, empty(), 0x9000, "Request for enc exponent resulted in SW: ");
            byte[] encryptionKeyExponent = rapdu.getData();
            
            if (!verifyKeyCertificate(encryptionKeyModulus, encryptionKeyExponent, encryptionKeyCertificate, cardVerifyKey)) {
                System.err.println("Invalid certificate for encryption key received");
                return false;
            }
            
            RSAPublicKey cardEncryptionKey = buildCardKeys(encryptionKeyModulus, encryptionKeyExponent);
            
            // Set the public field cardVerifyKey so it can be accessed.
            this.cardVerifyKey = cardVerifyKey;
            // Set the public field cardEncryptionKey so it can be accessed.
            this.cardEncryptionKey = cardEncryptionKey;
        } catch (CardException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }
    
    private CommandAPDU startAuthenticationProtocol() {
        return new CommandAPDU(0, Constants.START_AUTHENTICATION_PROTOCOL, 0, 0, null, 0);
    }
    
    private CommandAPDU modulus() {
        return new CommandAPDU(0, 0, 0, 0, Utils.unsignedByteFromBigInt(terminalPublicKey.getModulus()), 0);
    }
    
    private CommandAPDU exponent() {
        return new CommandAPDU(0, 0, 0, 0, Utils.unsignedByteFromBigInt(terminalPublicKey.getPublicExponent()), 0);
    }
    
    private CommandAPDU certificate() {
        return new CommandAPDU(0, 0, 0, 0, terminalKeyCertificate, 0);
    }
    
    private CommandAPDU challenge(byte[] nonce) {
        byte[] msg = ArrayUtils.addAll(Constants.CHALLENGE_TAG, nonce);
        return new CommandAPDU(0, 0, 0, 0, msg, 0);
    }
    
    private CommandAPDU readyForChallenge() {
        return new CommandAPDU(0, 0, 0, 0, null, 0);
    }
    
    private CommandAPDU respondToChallenge(byte[] response) {
        return new CommandAPDU(0, 0, 0, 0, response, 0);
    }
    
    private boolean isWellFormattedChallenge(byte[] challenge) {
        return ByteBuffer.wrap(Constants.CHALLENGE_TAG, 0, 3).equals(ByteBuffer.wrap(challenge,0,3));
    }
    
    private byte[] signChallenge(byte[] challenge, RSAPrivateKey signingKey) throws CardException {
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(signingKey);
            signer.update(challenge);
            return signer.sign();
        } catch (Exception e) {
            e.printStackTrace();
            throw new CardException("Failed to respond to challenge received by the card");
        }
    }
}
