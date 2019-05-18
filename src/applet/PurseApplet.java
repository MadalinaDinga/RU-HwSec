package applet;

import common.Constants;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import javacard.security.Signature;


public class PurseApplet extends Applet implements ISO7816 {

    /** Buffer in RAM */
    private static byte[] tmp;

    /*
     *        KEY MATERIAL
     */

    /** Own key pair */
    private KeyPair kp;
    private RSAPublicKey pubKey;
    private RSAPrivateKey privKey;
    /** EEPROM for holding own key certificate */
    private byte[] keyCertificate;

    /** Public key for verifying signatures within the PKI. */
    private RSAPublicKey masterVerifyKey;
    /** Signature for verification and signing. */
    private Signature signature;
    /** Cipher for encryption and decryption. */
    private Cipher cipher;

    /** For holding key of other party. */
    private RSAPublicKey otherKey;
    
    /*
     *        STATE 
     */

    /** The persistent state of the application, stored in EEPROM */
    private byte persistentState;
    private static final byte STATE_INIT = 0;
    private static final byte STATE_ISSUED = 1;
    /** The balance on the card stored in EEPROM */
    private short balance;
    /** The transient state of the application, stored in RAM. */
    private byte[] transientState;

    public PurseApplet() {
        // Create buffer
        tmp = JCSystem.makeTransientByteArray((short)256,JCSystem.CLEAR_ON_RESET);
        // Create state
        transientState = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_RESET);
        persistentState = STATE_INIT;
        balance = 0;
        // Create crypto primitives
        cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        
        // Creating keys
        kp = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        kp.genKeyPair();
        privKey = (RSAPrivateKey) kp.getPrivate();
        pubKey = (RSAPublicKey) kp.getPublic();

        otherKey = (RSAPublicKey) kp.getPublic();
        otherKey.clearKey();
        masterVerifyKey = (RSAPublicKey) kp.getPublic();
        masterVerifyKey.clearKey();
        // Reserve room for certificate
        keyCertificate = new byte[Constants.CERTIFICATE_LENGTH];
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        (new PurseApplet()).register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte instructionByte = buffer[OFFSET_INS];
        
        RSAPrivateKey privK;
        short len;

        /* Ignore the APDU that selects this applet... */
        if (selectingApplet()) {
            return;
        }

        switch(persistentState) {
            case STATE_INIT:
                /* This happens in a trusted invironment */
                switch(instructionByte) {
                    case Constants.INS_PUBLIC_EXPONENT:
                    send_own_public_exponent(apdu);
                    break;
                    case Constants.INS_PUBLIC_MODULUS:
                    send_own_public_modulus(apdu);
                    break;
                    case Constants.INS_STORE_KEY_CERTIFICATE:
                    store_own_certificate(apdu);
                    break;
                    case Constants.INS_STORE_MASTER_KEY:
                    store_public_master_key(apdu);
                    break;
                    case Constants.INS_ISSUE:
                    persistentState = STATE_ISSUED;
                    default:
                        ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                }
            break;
            case STATE_ISSUED:
                switch(instructionByte) {
                    case Constants.INS_PUBLIC_EXPONENT:
                        send_own_public_exponent(apdu);
                        break;
                    
                    case Constants.INS_PUBLIC_MODULUS:
                        send_own_public_modulus(apdu);
                        break;

                    case Constants.INS_KEY_CERTIFICATE:
                        send_own_public_key_certificate(apdu);
                        break;

                    default:
                        ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                }
            break;

        }
    }

    private void send_own_public_key_certificate(APDU apdu) {
        Util.arrayCopy(keyCertificate, (short) 0, apdu.getBuffer(), (short) 0, Constants.CERTIFICATE_LENGTH);
        apdu.setOutgoingAndSend((short) 0 , Constants.CERTIFICATE_LENGTH);
    }

    /**
     * Copies the public exponent of <code> pubKey </code> into the apdu buffer.
     * And set the <code>apdu</code> to outgoing.
     * @param apdu
     */
    private void send_own_public_exponent(APDU apdu) {
        short len = pubKey.getExponent(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Copies the public modulus of <code> pubKey </code> into the apdu buffer.
     * And set the <code>apdu</code> to outgoing.
     * @param apdu
     */
    private void send_own_public_modulus(APDU apdu) {
        short len = pubKey.getModulus(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Stores the certificate for its own public key. This method trusts the
     * other party and hence will not perform any checks.
     * @param apdu - The current apdu.
     */
    private void store_own_certificate(APDU apdu) {
        short len = readBuffer(apdu, tmp, (short) 0);
        Util.arrayCopy(tmp, (short) 0, keyCertificate, (short) 0, len);
    }

    /**
     * Stores the public master key of the PKI. This method trusts the other
     * party and hence will not perform any checks.
     * @param apdu
     */
    private void store_public_master_key(APDU apdu) {
        short len = readBuffer(apdu, tmp, (short) 0);
        if (apdu.getBuffer()[ISO7816.OFFSET_P1] == 0) {
            // store modulus
            masterVerifyKey.setModulus(tmp, (short) 0, len);
        } else if (apdu.getBuffer()[ISO7816.OFFSET_P1] == 1) {
            // store exponent
            masterVerifyKey.setExponent(tmp, (short) 0, len);
        }
    }

    /**
    * Copies <code>length</code> bytes of data (starting at
    * <code>OFFSET_CDATA</code>) from <code>apdu</code> to <code>dest</code>
    * (starting at <code>offset</code>).
    *
    * This method will set <code>apdu</code> to incoming.
    *
    * @param apdu the APDU.
    * @param dest destination byte array.
    * @param offset offset into the destination byte array.
    * @param length number of bytes to copy.
    */
   private short readBuffer(APDU apdu, byte[] dest, short offset) {
    byte[] buf = apdu.getBuffer();
    short readCount = apdu.setIncomingAndReceive();
    short i = 0;
    Util.arrayCopy(buf,OFFSET_CDATA,dest,offset,readCount);

    short length = (short) (buf[ISO7816.OFFSET_LC] & 0xff);

    while ((short)(i + readCount) < length) {
       i += readCount;
       offset += readCount;
       readCount = (short)apdu.receiveBytes(OFFSET_CDATA);
       Util.arrayCopy(buf,OFFSET_CDATA,dest,offset,readCount);
    }

    return length;

 }

}