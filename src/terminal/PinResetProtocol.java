/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package terminal;

import common.Constants;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author tom
 */
public class PinResetProtocol extends Protocol {
    
    private ReloadGUI gui;
    private String pin;
    private final RSAPublicKey cardEncryptionKey;
    private final RSAPublicKey cardVerifyKey;
    private final RSAPrivateKey terminalPrivateKey;
    
    
    public PinResetProtocol(ReloadGUI gui, String pin, 
            RSAPublicKey cardEncryptionKey, RSAPrivateKey terminalPrivateKey,
            RSAPublicKey cardVerifyKey) {
        this.gui = gui;
        this.pin = pin;
        System.out.println(cardEncryptionKey);
        this.cardEncryptionKey = cardEncryptionKey;
        this.terminalPrivateKey = terminalPrivateKey;
        this.cardVerifyKey = cardVerifyKey;
    }

    /**
     * Sets the pin of the card.
     * @param applet
     * @return true if successfully set pin, false otherwise.
     */
    @Override
    public boolean run(CardChannel applet) {
        ResponseAPDU rapdu;
        
        byte[] pinBytes = new byte[4];
        for(int i = 0; i < pinBytes.length; i++) {
            pinBytes[i] = (byte) Integer.parseInt("" + pin.toCharArray()[i]);
        }
        try {
            // Retrieve card nonce
            rapdu = sendCommand(applet, getNonce(), 0x9000, "Retrieving nonce resulted in SW: ");
            byte[] nonce = rapdu.getData();
            
            Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
            System.out.println(cardEncryptionKey);
            cipher.init(Cipher.ENCRYPT_MODE, cardEncryptionKey);
            cipher.update(pinBytes);
            // Encrypt PIN
            byte[] encPin = cipher.doFinal();
            // Send encrypted PIN
            rapdu = sendCommand(applet, pin(encPin), 0x9000, "Sending encrypted pin resulted in SW: ");

            // Prepare signature
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(terminalPrivateKey);
            signature.update(Constants.PIN_TAG);
            signature.update(nonce);
            signature.update(pinBytes);
            byte[] sig = signature.sign();
            // Send signature
            rapdu = sendCommand(applet, pinSignature(sig), 0x9000, "Sending signature over pin resulted in SW: ");
            
        } catch (Exception e) {
            System.err.println("Failed to execute protocol");
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private CommandAPDU getNonce() {
        return empty();
    }
    
    private CommandAPDU getSignature() {
        return empty();
    }

    private CommandAPDU pin(byte[] encPin) {
        return new CommandAPDU(0, 0, 0, 0, encPin, 0);
    }

    private CommandAPDU pinSignature(byte[] sig) {
        return new CommandAPDU(0, 0, 0, 0, sig, 0);
    }
    
}
