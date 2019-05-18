package applet;

import common.Constants.*;

import javacard.framework.*;
import javacard.security.*;
import javacard.security.KeyPair.*;
import javacardx.crypto.*;
import javacard.security.Signature;


public class EchoApplet extends Applet implements ISO7816 {

    private static KeyPair kp;
    private static PublicKey masterVerifyKey;
    private static Signature signature;
    /** Cipher for encryption and decryption. */
    Cipher cipher;

    /** Buffer in RAM */
    private static byte[] tmp;
    private static byte[] keyCertificate;

    /** The state of the application, stored in EEPROM */
    private byte persistentState;
    private static final byte PERSONALIZABLE = 0x00;

    private byte[] transientState;

    public EchoApplet() {
        tmp = JCSystem.makeTransientByteArray((short)256,JCSystem.CLEAR_ON_RESET);
    
        cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        kp = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        kp.genKeyPair();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        (new EchoApplet()).register(bArray, (short)(bOffset + 1), bArray[bOffset]);
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


        switch(instructionByte) {
            case INS_PUBLIC_EXPONENT:
                break;
            
            case INS_PUBLIC_MODULUS:
                break;

            case INS_KEY_CERTIFICATE:
                break;

            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }



        switch(instructionByte) {
            case INS_ECHO:
                len = readBuffer(apdu, tmp, (short) 0);
                Util.arrayCopy(tmp, (byte) 0, buffer, (short) 0, len);
                apdu.setOutgoingAndSend((short) 0, len);
                break;

            case INS_GIVE_KEY_EXP:
                privK = (RSAPrivateKey) kp.getPrivate();
                len = privK.getExponent(tmp, (short) 0);
                Util.arrayCopy(tmp, (short) 0, buffer, (short) 0, len);
                apdu.setOutgoingAndSend((short) 0, len);
                break;

            case INS_GIVE_KEY_MOD:
                privK = (RSAPrivateKey) kp.getPrivate();
                len = privK.getModulus(buffer, (short) 0);
                apdu.setOutgoingAndSend((short) 0, len);
                break;

            case INS_GIVE_KEY_PUB_EXP:
                RSAPublicKey pubkey = (RSAPublicKey) kp.getPublic();
                len = pubkey.getExponent(buffer, (short) 0);
                apdu.setOutgoingAndSend((short) 0, len);
                break;
            
            case INS_SIGN:
                short len_inp = readBuffer(apdu, tmp, (short) 0);
                signature.init(kp.getPrivate(), Signature.MODE_SIGN);
                short len_sig = signature.sign(tmp, (short) 0, len_inp, tmp, (short) len_inp);
                Util.arrayCopy(tmp, (short) len_inp, buffer, (short) 0, len_sig);
                apdu.setOutgoingAndSend( (short) 0, len_sig );
                break;

            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
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