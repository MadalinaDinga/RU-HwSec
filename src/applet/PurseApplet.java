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
    
    private RandomData random;

    private OwnerPIN pin;

    /*
     *        STATE
     */

    /** The persistent state of the application, stored in EEPROM */
    private byte persistentState;
    private static final byte STATE_INIT = 0;
    private static final byte STATE_ISSUED = 1;
    /** The balance on the card stored in EEPROM */
    private short balance;
    private short transactionCounter;
    /** The transient state of the application, stored in RAM. */
    private byte[] transientState;
    private static final short STATE_INDEX_CURRENT_PROTOCOL = 0;
    private static final short STATE_INDEX_STEP = 1;
    private static final short STATE_INDEX_PARTIAL_STEP = 2;
    private static final short STATE_INDEX_AUTHENTICATION_STATUS = 3;

    private static final byte NO_PROTOCOL = (byte) 0;
    private static final byte AUTHENTICATING = (byte) 1;
    private static final byte AUTHENTICATED = (byte) 2;
    private static final byte NOT_AUTHENTICATED = (byte) 3;
    private static final byte RELOAD = (byte) 4;
    private static final byte PAYMENT = (byte) 5;
    
    /*
                TAGS
    */
    private final byte[] CHALLENGE_TAG;

    public PurseApplet() {
        CHALLENGE_TAG = new byte[] {0, 1, 0, 1};
        // Create buffer
        // tmp = JCSystem.makeTransientByteArray((short)256,JCSystem.CLEAR_ON_DESELECT);
        tmp = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
        // Create state
        transientState = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        persistentState = STATE_INIT;
        balance = 0;
        transactionCounter = 0;
        // Create crypto primitives
        cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        // Creating keys
        kp = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        kp.genKeyPair();
        privKey = (RSAPrivateKey) kp.getPrivate();
        pubKey = (RSAPublicKey) kp.getPublic();

        otherKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false); // TODO: Research KeyEncryption interface
        otherKey.clearKey();
        masterVerifyKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false); // TODO: Research KeyEncryption interface
        masterVerifyKey.clearKey();
        // Reserve room for certificate
        keyCertificate = new byte[Constants.CERTIFICATE_LENGTH];
        // Set the pin
        pin = new OwnerPIN((byte) 3, (byte) 4);
        tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
        pin.update(tmp, (short) 0, (byte) 4);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        (new PurseApplet()).register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte instructionByte = buffer[OFFSET_INS];
        
        short len;

        /* Ignore the APDU that selects this applet... */
        if (selectingApplet()) {
            clearTransientState();
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
                switch(transientState[STATE_INDEX_CURRENT_PROTOCOL]) {
                    case NO_PROTOCOL:
                        switch(instructionByte) {
                            case Constants.START_AUTHENTICATION_PROTOCOL:
                                transientState[STATE_INDEX_CURRENT_PROTOCOL] = AUTHENTICATING;
                                transientState[STATE_INDEX_STEP] = 0;
                                transientState[STATE_INDEX_PARTIAL_STEP] = 0;
                                break;
                            case Constants.START_RELOAD_PROTOCOL:
                                if (isAuthenticated()) {
                                    transientState[STATE_INDEX_CURRENT_PROTOCOL] = RELOAD;
                                    transientState[STATE_INDEX_STEP] = 0;
                                    transientState[STATE_INDEX_PARTIAL_STEP] = 0;
                                } else {
                                    ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
                                }
                                break;
                            case Constants.START_PAYMENT_PROTOCOL:
                                if (isAuthenticated()) {
                                    transientState[STATE_INDEX_CURRENT_PROTOCOL] = PAYMENT;
                                    transientState[STATE_INDEX_STEP] = 0;
                                    transientState[STATE_INDEX_PARTIAL_STEP] = 0;
                                } else {
                                    ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
                                }
                                break;

                            default:
                                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                        }
                        apdu.setOutgoingAndSend((short) 0, (short) 0);
                        break;
                    default:
                        ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                        break;
                    case AUTHENTICATING:
                        switch(transientState[STATE_INDEX_STEP]) {
                            case 0:
                                // Receive public modulus
                                len = readBuffer(apdu, tmp, (short) 0);
                                otherKey.setModulus(tmp,(short) 0, len);
                                // Send public modulus
                                send_own_public_modulus(apdu);
                                transientState[STATE_INDEX_STEP]++;
                                break;
                            case 1:
                                // Receive public exponent
                                len = readBuffer(apdu, tmp, (short) 0);
                                otherKey.setExponent(tmp, (short) 0, len);
                                // Send own exponent
                                send_own_public_exponent(apdu);
                                transientState[STATE_INDEX_STEP]++;
                                break;
                            case 2:
                                if (verifyCertificate(apdu)) {
                                    send_own_public_key_certificate(apdu);
                                    transientState[STATE_INDEX_STEP]++;
                                } else {
                                    clearTransientState();
                                    ISOException.throwIt(Constants.SW_CERTIFICATE_CHECK_FAILED);
                                }
                                break;
                            case 3:
                                /* Expected is a plain challenge, we must respond with the signature on it */
                                len = readBuffer(apdu, tmp, (short) 0);
                                
                                if ((byte) 0x00 == Util.arrayCompare(tmp, (short) 0, CHALLENGE_TAG, (short) 0, (short) CHALLENGE_TAG.length)) {
                                    
                                    signature.init(privKey, Signature.MODE_SIGN);
                                    short lenSig = signature.sign(tmp, (short) 0, len, apdu.getBuffer(), (short) 0);
                                    
                                    transientState[STATE_INDEX_STEP]++;
                                    apdu.setOutgoingAndSend((short) 0, lenSig);
                                } else {
                                    ISOException.throwIt((short) 0x00);
                                }
                                break;
                            case 4:
                                /* Don't expect any data, return a challenge */
                                apdu.setIncomingAndReceive();
                                random.generateData(tmp, (short) CHALLENGE_TAG.length, Constants.CHALLENGE_LENGTH);
                                Util.arrayCopy(CHALLENGE_TAG, (short) 0, tmp, (short) 0, (short) CHALLENGE_TAG.length);
                                Util.arrayCopy(tmp, (short) 0, apdu.getBuffer(), (short) 0, (short) (CHALLENGE_TAG.length + Constants.CHALLENGE_LENGTH));
                                
                                apdu.setOutgoingAndSend((short) 0, (short) (CHALLENGE_TAG.length + Constants.CHALLENGE_LENGTH));
                                transientState[STATE_INDEX_STEP]++;
                                break;
                            case 5:
                                /* Verify signature on the challenge. */
                                short challengeLength = (short) (CHALLENGE_TAG.length + Constants.CHALLENGE_LENGTH);
                                len = readBuffer(apdu, tmp, challengeLength);
                                signature.init(otherKey, Signature.MODE_VERIFY);
                                if (signature.verify(tmp, (short) 0, challengeLength, tmp, challengeLength, len))  {
                                    transientState[STATE_INDEX_STEP]++;
                                    apdu.setOutgoingAndSend((short) 0, (short) 0);
                                    setAuthenticated(true);
                                    transientState[STATE_INDEX_CURRENT_PROTOCOL] = NO_PROTOCOL;
                                } else {
                                    clearTransientState();
                                    ISOException.throwIt(Constants.SW_CHALLENGE_FAILED); //TODO: Failing message
                                }
                                break;
                        }
                        break;
                    case RELOAD:

                        break;
                    case PAYMENT:
                        switch(transientState[STATE_INDEX_STEP]) {
                            case 0:
                                if (! isAuthenticated()) {
                                    ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                                    clearTransientState();
                                } else {
                                    // TMP contents:: Amount
                                    len = readBuffer(apdu, tmp, (short) 0);
                                    transientState[STATE_INDEX_PARTIAL_STEP] = (byte) len;
                                    
                                    if (Util.makeShort((byte) 0x00, transientState[STATE_INDEX_PARTIAL_STEP]) > 2
                                            || Util.makeShort((byte) 0x00, transientState[STATE_INDEX_PARTIAL_STEP]) < 0) {
                                        ISOException.throwIt(Constants.SW_INVALID_AMOUNT);
                                        clearTransientState();
                                    } else if (Util.makeShort(tmp[0], tmp[1]) > balance) {
                                        clearTransientState();
                                        ISOException.throwIt(Constants.SW_INSUFFICIENT_BALANCE);
                                    }
                                    
                                    Util.setShort(apdu.getBuffer(), (short) 0, transactionCounter); 
                                    apdu.setOutgoingAndSend((short) 0, (short) 2);
                                    transientState[STATE_INDEX_STEP]++;
                                }
                                break;
                            case 1:
                                // TMP contents:: Amount, nonce_t
                                len = readBuffer(apdu, tmp, Util.makeShort((byte) 0x00, transientState[STATE_INDEX_PARTIAL_STEP]));
                                Util.setShort(tmp, (short) (len + transientState[STATE_INDEX_PARTIAL_STEP]), transactionCounter);
                                signature.init(privKey, Signature.MODE_SIGN);
                                transientState[STATE_INDEX_PARTIAL_STEP] = (byte) (2 + transientState[STATE_INDEX_PARTIAL_STEP] + len); 
                                short length = signature.sign(tmp, (short) 0, (short) (transientState[STATE_INDEX_PARTIAL_STEP]), apdu.getBuffer(), (short) 0);
                                apdu.setOutgoingAndSend((short) 0, length);
                                transientState[STATE_INDEX_STEP]++;
                                break;
                            case 2:
                                // length of Amount + nonce + transactionCounter
                                short off = Util.makeShort((byte) 0x00, transientState[STATE_INDEX_PARTIAL_STEP]);
                                // Expect signature over data for checking integrity.
                                len = readBuffer(apdu, tmp, off);
                                signature.init(otherKey, Signature.MODE_VERIFY);
                                if (signature.verify(tmp, (short) 0, off, tmp, off, len)) {
                                    short modOff = otherKey.getModulus(tmp, off);
                                    short expOff = otherKey.getExponent(tmp, (short) (modOff + off));
                                    signature.init(privKey, Signature.MODE_SIGN);
                                    len = signature.sign(tmp, (short) 0, (short) (off + modOff + expOff), apdu.getBuffer(), (short) 0);
                                    balance -= Util.makeShort(tmp[0], tmp[1]); 
                                    apdu.setOutgoingAndSend((short) 0, len);
                                    transactionCounter++;
                                    clearTransientState();
                                } else {
                                    clearTransientState();
                                    ISOException.throwIt(SW_DATA_INVALID);
                                }
                            }
                        break;
                }
                break;
        }
    }

    private boolean isAuthenticated() {
        return transientState[STATE_INDEX_AUTHENTICATION_STATUS] == AUTHENTICATED;
    }

    private void setAuthenticated(boolean val) {
        transientState[STATE_INDEX_AUTHENTICATION_STATUS] = (val) ? AUTHENTICATED : NOT_AUTHENTICATED;
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
     * Verifies if the certificate in the <code>apdu</code> buffer is a valid
     * signature on the current value of <code>otherKey</code>.
     * @param apdu
     * @return true if certificate is valid, false otherwise.
     * @throws SW_DATA_INVALID if signature is incorrect.
     */
    private boolean verifyCertificate(APDU apdu) {
        signature.init(masterVerifyKey, Signature.MODE_VERIFY);
        short mLen = otherKey.getModulus(tmp, (short) 0);
        short tLen = otherKey.getExponent(tmp, mLen);
        short len = readBuffer(apdu, tmp, (short) (mLen + tLen + 1));
        if (signature.verify(tmp, (short) 0, (short) (mLen + tLen), tmp, (short) (mLen + tLen + 1), len /* Constants.CERTIFICATE_LENGTH */)) {
            return true;
        } else {
            clearTransientState();
            ISOException.throwIt(Constants.SW_CERTIFICATE_CHECK_FAILED);
            return false;
        }
    }

    /**
     * Resets the transient state as if no communication has happened yet.
     */
    private void clearTransientState() {
        setAuthenticated(false);
        otherKey.clearKey();
        transientState[STATE_INDEX_CURRENT_PROTOCOL] = NO_PROTOCOL;
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