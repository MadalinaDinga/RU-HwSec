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
   /** Card public signing key */
   private RSAPublicKey pubKey;
   /** Card private signing key */
   private RSAPrivateKey privKey;
   /** Container for key pair, used for key generation */
   private KeyPair encKP;
   /** Card encryption (public) key */
   private RSAPublicKey encKey;
   /** Card decryption (private) key */
   private RSAPrivateKey decKey;
   /** Own key certificate in EEPROM*/
   private byte[] keyCertificate;
   /** Signed own key certificate */
   private byte[] encKeyCertificate;

    /** Public key for verifying signatures within the PKI */
    private RSAPublicKey masterVerifyKey;
    /** Signature for verification and signing */
    private Signature signature;
    /** Cipher for encryption and decryption */
    private Cipher cipher;

    /** For holding key of other party */
    private RSAPublicKey otherKey;
    /** Random data generator object */
    private RandomData random;
    /** Own pin code */
    private OwnerPIN pin;

    /*
     *        STATE
     */

    /** The persistent state of the application, stored in EEPROM */
    private byte persistentState;
    /** State before personalization */
    private static final byte STATE_INIT = 0;
    /** State after personalization */
    private static final byte STATE_ISSUED = 1;
    /** State after the card has been blocked */
    private static final byte STATE_BLOCKED = 3;

    /** The balance on the card, stored in EEPROM */
    private short balance;
    /** The transaction counter, stored in EEPROM */
    private short transactionCounter;
    /** Whether pin reset is required, stored in EEPROM */
    private boolean pin_reset_required;

    /** The transient state of the application, stored in RAM. */
    private byte[] transientState;
    /** tmp offset, stored in RAM */
    private short[] offset;
    /** The current protocol state, stored in RAM */
    private static final short STATE_INDEX_CURRENT_PROTOCOL = 0;
    /** The current step inside the protocol, stored in RAM */
    private static final short STATE_INDEX_STEP = 1;

    /** Authentication status (AUTHENTICATED/NOT_AUTHENTICATED) */
    private static final short STATE_INDEX_AUTHENTICATION_STATUS = 2;


    private static final byte NO_PROTOCOL = (byte) 0;
    private static final byte AUTHENTICATING = (byte) 1;
    private static final byte AUTHENTICATED = (byte) 2;
    private static final byte NOT_AUTHENTICATED = (byte) 3;
    private static final byte RELOAD = (byte) 4;
    private static final byte PAYMENT = (byte) 5;
    private static final byte PIN_RESET = (byte) 6;
    
    /** TAGS used for signing, following pattern 0 1 0 x (less circumventable)
     * Every signed message type should have a unique tag.
     */
    private final byte[] CHALLENGE_TAG;
    private final byte[] PIN_TAG;
    public final byte[] PAYMENT_TAG;
    public final byte[] RELOAD_TAG;


    public PurseApplet() {
        // Initialize transient/persistent memory
        initializeMemoryState();

        // Create crypto primitives
        cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        // Initialize keys and certificates
        initializeKeyMaterial();

        // Set the default pin
        setDefaultPIN();

        // Initialize signing tags
        CHALLENGE_TAG = new byte[] { 0, 1, 0, 1 };
        PIN_TAG = new byte[] { 0, 1, 0, 2 };
        PAYMENT_TAG = new byte[] {0, 1, 0, 3};
        RELOAD_TAG = new byte[] {0, 1, 0, 4};
    

        clearTransientState();
    }

    /**
     * Prepare KEY MATERIAL:
     *  generate signing keys,
     *  generate encryption keys, 
     *  encrypt own certificate,
     *  reserve room for terminal keys, key certificate
     */
    private void initializeKeyMaterial() {
        // Create signing keys
        kp = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        kp.genKeyPair();
        privKey = (RSAPrivateKey) kp.getPrivate();
        pubKey = (RSAPublicKey) kp.getPublic();

        // Create encryption keys
        encKP = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        encKP.genKeyPair();
        encKey = (RSAPublicKey) kp.getPublic();
        decKey = (RSAPrivateKey) kp.getPrivate();

        // Self sign certificate
        encKeyCertificate = new byte[Constants.CERTIFICATE_LENGTH];
        signature.init(privKey, Signature.MODE_SIGN);
        short modLen = encKey.getModulus(tmp, (short) 0);
        short expLen = encKey.getExponent(tmp, modLen);
        signature.sign(tmp, (short) 0, (short) (modLen + expLen), encKeyCertificate, (short) 0);

        // Initialize space for storing keys
        otherKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false); // TODO:
                                                                                                                      // Research
                                                                                                                      // KeyEncryption                                                                                                          // interface
        otherKey.clearKey();
        masterVerifyKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024,
                false); // TODO: Research KeyEncryption interface
        masterVerifyKey.clearKey();

        // Reserve room for certificate
        keyCertificate = new byte[Constants.CERTIFICATE_LENGTH];
    }

    /**
     * Initialize card transient and persistent state.
     */
    private void initializeMemoryState() {
        // Create transient/temporary memory buffer
        tmp = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
        // Create state
        transientState = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);
        offset = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        
        // The card is in an uninitialized state until it goes through the initialization protocol (i.e.,
        // personalization) - CLI
        persistentState = STATE_INIT;
        // No balance on card until first reload.
        balance = 0;
        // Should increase after every successfully performed transaction.
        transactionCounter = 0;
    }

    /** 
     * Set default PIN code to 0 0 0 0
     */
    private void setDefaultPIN() {
        // Construct PIN code with try limit set to 3 and maximum PIN size 4.
        pin = new OwnerPIN((byte) 3, (byte) 4);
        tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
        pin.update(tmp, (short) 0, (byte) 4);
        // The PIN needs to be reset before being able to reload.
        pin_reset_required = true;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        (new PurseApplet()).register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte instructionByte = buffer[OFFSET_INS];
        
        short len = 0;

        /* Ignore the APDU that selects this applet... */
        if (selectingApplet()) {
            clearTransientState();
            return;
        }
        
        if (persistentState == STATE_BLOCKED) {
            ISOException.throwIt((short) 0x00);
        }

        switch(persistentState) {
            case STATE_INIT:
                /* This happens in a trusted invironment */
                performInitialization(apdu, instructionByte);
                break;
            case STATE_ISSUED:
                switch (transientState[STATE_INDEX_CURRENT_PROTOCOL]) {
                case NO_PROTOCOL:
                    startProtocol(apdu, instructionByte);
                    break;
                case AUTHENTICATING:
                    performAuthProtocol(apdu, len);
                    break;
                case PIN_RESET:
                    performPinResetProtocol(apdu, len);
                    break;
                case RELOAD:
                    performReloadProtocol(apdu, len);
                    break;
                case PAYMENT:
                    performPaymentProtocol(apdu, len);
                    break;
                default:
                    ISOException.throwIt(SW_INS_NOT_SUPPORTED);
                    break;
                }
                break;
        }
    }

    private void performInitialization(APDU apdu, byte instructionByte) {
        switch (instructionByte) {
            case Constants.INS_PUBLIC_EXPONENT:
                send_own_public_exponent(apdu);
                break;
            case Constants.INS_PUBLIC_MODULUS:
                send_own_public_modulus(apdu);
                break;
            case Constants.INS_STORE_KEY_CERTIFICATE:
                store_own_certificate(apdu);
                apdu.setOutgoingAndSend((short) 0, (short) 0);
                break;
            case Constants.INS_STORE_MASTER_KEY:
                store_public_master_key(apdu);
                apdu.setOutgoingAndSend((short) 0, (short) 0);
                break;
            case Constants.INS_ISSUE:
                persistentState = STATE_ISSUED;
                apdu.setOutgoingAndSend((short) 0, (short) 0);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
    }

    /** Starts the protocol required by the terminal */
    private void startProtocol(APDU apdu, byte instructionByte) {
        switch (instructionByte) {
        case Constants.START_AUTHENTICATION_PROTOCOL:
            transientState[STATE_INDEX_CURRENT_PROTOCOL] = AUTHENTICATING;
            transientState[STATE_INDEX_STEP] = 0;
            break;
        case Constants.START_RELOAD_PROTOCOL:
            if (!isAuthenticated()) {
                ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
                break;
            }

            // If PIN reset is required, start the PIN_RESET protocol, otherwise continue with the RELOAD protocol
            if (pin_reset_required) {
                transientState[STATE_INDEX_CURRENT_PROTOCOL] = PIN_RESET;
                transientState[STATE_INDEX_STEP] = 0;
                // Notify Reload terminal of PIN_RESET PROTOCOL.
                ISOException.throwIt(Constants.SW_RESET_PIN);
            } else {
                transientState[STATE_INDEX_CURRENT_PROTOCOL] = RELOAD;
                transientState[STATE_INDEX_STEP] = 0;
            }
            break;
        case Constants.START_PAYMENT_PROTOCOL:
            if (!isAuthenticated()) {
                ISOException.throwIt(SW_COMMAND_NOT_ALLOWED);
                break;
            }
            transientState[STATE_INDEX_CURRENT_PROTOCOL] = PAYMENT;
            transientState[STATE_INDEX_STEP] = 0;
            break;
        default:
            ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }

    /** Performs the mutual authentication protocol */
    private void performAuthProtocol(APDU apdu, short len) {
        switch (transientState[STATE_INDEX_STEP]) {
        case 0:
            // Receive public modulus
            len = readBuffer(apdu, tmp, (short) 0);
            otherKey.setModulus(tmp, (short) 0, len);
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

            if ((byte) 0x00 == Util.arrayCompare(tmp, (short) 0, CHALLENGE_TAG, (short) 0,
                    (short) CHALLENGE_TAG.length)) {

                signature.init(privKey, Signature.MODE_SIGN);
                short lenSig = signature.sign(tmp, (short) 0, len, apdu.getBuffer(), (short) 0);

                transientState[STATE_INDEX_STEP]++;
                apdu.setOutgoingAndSend((short) 0, lenSig);
            } else {
                ISOException.throwIt((short) Constants.SW_WRONG_FORMAT);
            }
            break;
        case 4:
            /* Don't expect any data, return a challenge */
            apdu.setIncomingAndReceive();
            random.generateData(tmp, (short) CHALLENGE_TAG.length, Constants.CHALLENGE_LENGTH);
            Util.arrayCopy(CHALLENGE_TAG, (short) 0, tmp, (short) 0, (short) CHALLENGE_TAG.length);
            Util.arrayCopy(tmp, (short) 0, apdu.getBuffer(), (short) 0,
                    (short) (CHALLENGE_TAG.length + Constants.CHALLENGE_LENGTH));

            apdu.setOutgoingAndSend((short) 0, (short) (CHALLENGE_TAG.length + Constants.CHALLENGE_LENGTH));
            transientState[STATE_INDEX_STEP]++;
            break;
        case 5:
            /* Verify signature on the challenge. */
            short challengeLength = (short) (CHALLENGE_TAG.length + Constants.CHALLENGE_LENGTH);
            len = readBuffer(apdu, tmp, challengeLength);
            signature.init(otherKey, Signature.MODE_VERIFY);
            if (signature.verify(tmp, (short) 0, challengeLength, tmp, challengeLength, len)) {
                transientState[STATE_INDEX_STEP]++;
                Util.arrayCopy(encKeyCertificate, (short) 0, apdu.getBuffer(), (short) 0, Constants.CERTIFICATE_LENGTH);
                apdu.setOutgoingAndSend((short) 0, Constants.CERTIFICATE_LENGTH);
            } else {
                clearTransientState();
                ISOException.throwIt(Constants.SW_CHALLENGE_FAILED); // TODO: Failing message
            }
            break;
        case 6:
            /* Send out encryption key */
            len = readBuffer(apdu, tmp, (short) 0);
            len = encKey.getModulus(apdu.getBuffer(), (short) 0);
            apdu.setOutgoingAndSend((short) 0, len);
            transientState[STATE_INDEX_STEP]++;
            break;
        case 7:
            /* Send out encryption key */
            len = readBuffer(apdu, tmp, (short) 0);
            len = encKey.getExponent(apdu.getBuffer(), (short) 0);
            apdu.setOutgoingAndSend((short) 0, len);
            transientState[STATE_INDEX_STEP]++;
            setAuthenticated(true);
            transientState[STATE_INDEX_CURRENT_PROTOCOL] = NO_PROTOCOL;
            break;
        }
    }

    /** Performs the PIN reset protocol, started at first reload */
    private void performPinResetProtocol(APDU apdu, short len) {
        switch (transientState[STATE_INDEX_STEP]) {
        case 0:
            // TMP: PIN_TAG
            Util.arrayCopy(PIN_TAG, (short) 0, tmp, (short) 0, (short) PIN_TAG.length);
            offset[0] = (short) PIN_TAG.length;
            // TMP: PIN_TAG, nonce
            random.generateData(tmp, offset[0], Constants.CHALLENGE_LENGTH);
            offset[0] += Constants.CHALLENGE_LENGTH;
            Util.arrayCopy(tmp, (short) PIN_TAG.length, apdu.getBuffer(), (short) 0, Constants.CHALLENGE_LENGTH);
            apdu.setOutgoingAndSend((short) 0, Constants.CHALLENGE_LENGTH);
            transientState[STATE_INDEX_STEP]++;
            break;
        case 1:
            // TMP: PIN_TAG, nonce, PIN
            // Receive and decrypt PIN 
            len = readBuffer(apdu, tmp, offset[0]);
            cipher.init(decKey, Cipher.MODE_DECRYPT);
            len = cipher.doFinal(tmp, offset[0], len, tmp, offset[0]);
            if (len != 4) {
                ISOException.throwIt(SW_DATA_INVALID);
                clearTransientState();
            } else {
                offset[0] += 4;
                transientState[STATE_INDEX_STEP]++;
            }
            break;
        case 2:
            // Receive signature
            len = readBuffer(apdu, tmp, offset[0]);
            signature.init(otherKey, Signature.MODE_VERIFY);
            // Verify signature and throw exception if it fails
            if (!signature.verify(tmp, (short) 0, offset[0], tmp, offset[0], len)) {
                ISOException.throwIt(SW_DATA_INVALID);
                clearTransientState();
                break;
            } 
            // Reset PIN, if signature verification successful
            pin.update(tmp, (short) (offset[0] - 4), (byte) 4);
            // Change internal state of the card (pin reset flag to false)
            pin_reset_required = false;
            transientState[STATE_INDEX_CURRENT_PROTOCOL] = NO_PROTOCOL;
            break;
        }
    }

    /** Performs the protocol for reload transactions. */
    private void performReloadProtocol(APDU apdu, short len) {
        switch (transientState[STATE_INDEX_STEP]) {
        case 0:
            if (!isAuthenticated()) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                clearTransientState();
                break;
            }
            // TMP contents:: RELOAD_TAG
            Util.arrayCopy(RELOAD_TAG, (short) 0, tmp, (short) 0, (short) RELOAD_TAG.length);
            offset[0] = (short) RELOAD_TAG.length;

            // TMP contents:: RELOAD_TAG, Amount
            len = readBuffer(apdu, tmp, (short) 0);
            offset[0] += len;

            if (offset[0] > 2 || offset[0] < 0) {
                ISOException.throwIt(Constants.SW_INVALID_AMOUNT);
                clearTransientState();
            }

            Util.setShort(apdu.getBuffer(), (short) 0, transactionCounter);
            apdu.setOutgoingAndSend((short) 0, (short) 2);
            transientState[STATE_INDEX_STEP]++;

            break;
        case 1:
            // TMP contents:: RELOAD_TAG, Amount, nonce_t
            offset[0] += readBuffer(apdu, tmp, offset[0]);
            // TMP contents:: RELOAD_TAG, Amount, nonce_t, transactionCounter
            Util.setShort(tmp, (short) (offset[0]), transactionCounter);
            offset[0] += 2;

            signature.init(privKey, Signature.MODE_SIGN);
            len = signature.sign(tmp, (short) 0, (short) offset[0], apdu.getBuffer(), (short) 0);
            apdu.setOutgoingAndSend((short) 0, len);
            transientState[STATE_INDEX_STEP]++;
            break;
        case 2:
            // Expect signature over data for checking integrity.
            len = readBuffer(apdu, tmp, offset[0]);
            signature.init(otherKey, Signature.MODE_VERIFY);
            if (signature.verify(tmp, (short) 0, offset[0], tmp, offset[0], len)) {
                short modOff = otherKey.getModulus(tmp, offset[0]);
                short expOff = otherKey.getExponent(tmp, (short) (modOff + offset[0]));
                signature.init(privKey, Signature.MODE_SIGN);
                len = signature.sign(tmp, (short) 0, (short) (offset[0] + modOff + expOff), apdu.getBuffer(),
                        (short) 0);
                
                short amount = Util.makeShort(tmp[0], tmp[1]);
                // Validate amount.
                if (!isValidAmount(amount)) {
                    ISOException.throwIt(Constants.SW_INVALID_AMOUNT);
                }
                // Increase balance by given amount.
                balance += amount;
                apdu.setOutgoingAndSend((short) 0, len);
                transactionCounter++;
            } else {
                clearTransientState();
                ISOException.throwIt(SW_DATA_INVALID);
            }
            clearTransientState();
        }
    }

    /** Performs the protocol for payment transactions. */
    private void performPaymentProtocol(APDU apdu, short len) {
        switch (transientState[STATE_INDEX_STEP]) {
        case 0:
            if (!isAuthenticated()) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
                clearTransientState();
                break;
            } 
            // TMP contents:: PAYMENT_TAG
            Util.arrayCopy(PAYMENT_TAG, (short) 0, tmp, (short) 0, (short) PAYMENT_TAG.length);
            offset[0] = (short) PAYMENT_TAG.length;
            
            // TMP contents:: PAYMENT_TAG, Amount
            len = readBuffer(apdu, tmp, (short) 0);
            offset[0] += len;

            if (offset[0] > 2 || offset[0] < 0) {
                ISOException.throwIt(Constants.SW_INVALID_AMOUNT);
                clearTransientState();
            } else if (Util.makeShort(tmp[0], tmp[1]) > balance) {
                clearTransientState();
                ISOException.throwIt(Constants.SW_INSUFFICIENT_BALANCE);
            }

            Util.setShort(apdu.getBuffer(), (short) 0, transactionCounter);
            random.generateData(apdu.getBuffer(), (short) 2, Constants.CHALLENGE_LENGTH);
            offset[0] += Constants.CHALLENGE_LENGTH + (short) 2;
            // TMP contents:: PAYMENT_TAG, Amount, transactionCounter, nonce
            Util.arrayCopy(apdu.getBuffer(), (short) 0, tmp, (short) 2, offset[0]);

            apdu.setOutgoingAndSend((short) 0, (short) (2 + Constants.CHALLENGE_LENGTH));
            transientState[STATE_INDEX_STEP]++;
        
            break;
        case 1:
            // TMP contents:: PAYMENT_TAG, Amount, transactionCounter, nonce, nonce_t
            offset[0] += readBuffer(apdu, tmp, offset[0]);

            signature.init(privKey, Signature.MODE_SIGN);
            len = signature.sign(tmp, (short) 0, (short) offset[0], apdu.getBuffer(), (short) 0);
            apdu.setOutgoingAndSend((short) 0, len);
            transientState[STATE_INDEX_STEP]++;
            break;
        case 2:
            // Receive and decrypt pin
            len = readBuffer(apdu, tmp, offset[0]);
            cipher.init(decKey, Cipher.MODE_DECRYPT);
            len = cipher.doFinal(tmp, offset[0], len, tmp, offset[0]);
            // Check if the encryption is fresh
            byte nonceOk = Util.arrayCompare(tmp, (short) (offset[0] + 4 + 2), tmp, (short) 4,
                    Constants.CHALLENGE_LENGTH);
            if (pin.check(tmp, (short) (offset[0]), (byte) 4) && nonceOk == 0) {
                transientState[STATE_INDEX_STEP]++;
                ISOException.throwIt(SW_NO_ERROR);
            } else {
                byte tries = pin.getTriesRemaining();
                if (tries == (byte) 0x00) {
                    // Block the card
                    persistentState = STATE_BLOCKED;
                    clearTransientState();
                    ISOException.throwIt(Constants.SW_BLOCKED);
                } else {
                    apdu.getBuffer()[0] = tries;
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    ISOException.throwIt(Constants.SW_WRONG_PIN);
                }
            }
            break;
        case 3:
            // Expect signature over data for checking integrity.
            len = readBuffer(apdu, tmp, offset[0]);
            signature.init(otherKey, Signature.MODE_VERIFY);
            if (signature.verify(tmp, (short) 0, offset[0], tmp, offset[0], len)) {
                short modOff = otherKey.getModulus(tmp, offset[0]);
                short expOff = otherKey.getExponent(tmp, (short) (modOff + offset[0]));
                signature.init(privKey, Signature.MODE_SIGN);
                len = signature.sign(tmp, (short) 0, (short) (offset[0] + modOff + expOff), apdu.getBuffer(),
                        (short) 0);
                
                short amount = Util.makeShort(tmp[0], tmp[1]);
                // Validate amount.
                if (!isValidAmount(amount)) {
                    ISOException.throwIt(Constants.SW_INVALID_AMOUNT);
                }
                // Decrease balance by given amount.
                balance -= amount;
                apdu.setOutgoingAndSend((short) 0, len);
                transactionCounter++;
                clearTransientState();
            } else {
                clearTransientState();
                ISOException.throwIt(SW_DATA_INVALID);
            }
            break;
        }
    }

    /** Validate transaction amount */
    private boolean isValidAmount(short amount) {
        // Transaction amount cannot be 0 or negative
        if (amount <= 0) {
            return false;
        }
        return true;
    }

    /** Checks whether the card is authenticated */
    private boolean isAuthenticated() {
        return transientState[STATE_INDEX_AUTHENTICATION_STATUS] == AUTHENTICATED;
    }

    /** Changes the authentification state of the card */
    private void setAuthenticated(boolean val) {
        transientState[STATE_INDEX_AUTHENTICATION_STATUS] = (val) ? AUTHENTICATED : NOT_AUTHENTICATED;
    }

    /** Sends the card public key certificate */
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
     */
    private boolean verifyCertificate(APDU apdu) {
        signature.init(masterVerifyKey, Signature.MODE_VERIFY);
        short mLen = otherKey.getModulus(tmp, (short) 0);
        short eLen = otherKey.getExponent(tmp, mLen);
        short len = readBuffer(apdu, tmp, (short) (mLen + eLen + 1));
        return signature.verify(tmp, (short) 0, (short) (mLen + eLen), tmp, (short) (mLen + eLen + 1), len); 
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