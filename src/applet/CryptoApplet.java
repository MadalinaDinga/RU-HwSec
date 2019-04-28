/*
 * $Id: CryptoApplet.java,v 1.1 2004/06/09 13:37:07 martijno Exp $
 */

package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * Class CryptoApplet.
 *
 * @author Martijn Oostdijk (martijno@cs.kun.nl)
 *
 * @version $Revision: 1.1 $
 */
public class CryptoApplet extends Applet implements ISO7816
{
   private static final byte INS_SET_PUB_MODULUS = (byte)0x02;
   private static final byte INS_SET_PRIV_MODULUS = (byte)0x12;
   private static final byte INS_SET_PRIV_EXP = (byte)0x22;
   private static final byte INS_SET_PUB_EXP = (byte)0x32;
   private static final byte INS_ISSUE = (byte)0x40;

   private static final byte INS_ENCRYPT = (byte)0xE0;
   private static final byte INS_DECRYPT = (byte)0xD0;

   private static final byte STATE_INIT = 0;
   private static final byte STATE_ISSUED = 1;

   /** Temporary buffer in RAM. */
   byte[] tmp;

   /** The applet state (INIT or ISSUED). */
   byte state;

   /** Key for encryption. */
   RSAPublicKey pubKey;

   /** Key for decryption. */
   RSAPrivateKey privKey;

   /** Cipher for encryption and decryption. */
   Cipher cipher;

   public static void install(byte[] bArray, short bOffset, byte bLength){
      (new CryptoApplet()).register(bArray, (short)(bOffset + 1), bArray[bOffset]);
   }

   public CryptoApplet() {
      tmp = JCSystem.makeTransientByteArray((short)256,JCSystem.CLEAR_ON_RESET);
      pubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,
                                             KeyBuilder.LENGTH_RSA_1024,false);
      privKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
                                             KeyBuilder.LENGTH_RSA_1024,false);
      cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1,false);
      state = STATE_INIT;
   }

   public void process(APDU apdu){
      byte[] buf = apdu.getBuffer();
      byte ins = buf[OFFSET_INS];
      short lc = (short)(buf[OFFSET_LC] & 0x00FF);
      short outLength;

      if (selectingApplet()) {
         return;
      }

      switch(state) {
         case STATE_INIT:
            switch(ins){
               case INS_SET_PUB_MODULUS:
                  readBuffer(apdu,tmp,(short)0,lc);
                  pubKey.setModulus(tmp,(short)0,lc);
                  break;
               case INS_SET_PRIV_MODULUS:
                  readBuffer(apdu,tmp,(short)0,lc);
                  privKey.setModulus(tmp,(short)0,lc);
                  break;
               case INS_SET_PUB_EXP:
                  readBuffer(apdu,tmp,(short)0,lc);
                  pubKey.setExponent(tmp,(short)0,lc);
                  break;
               case INS_SET_PRIV_EXP:
                  readBuffer(apdu,tmp,(short)0,lc);
                  privKey.setExponent(tmp,(short)0,lc);
                  break;
               case INS_ISSUE:
                  state = STATE_ISSUED;
                  break;
               default:
                  ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            }
            break;
         case STATE_ISSUED:
            switch(ins) {
               case INS_ENCRYPT:
                  readBuffer(apdu,tmp,(short)0,lc);
                  apdu.setOutgoing();
                  cipher.init(pubKey,Cipher.MODE_ENCRYPT);
                  outLength = cipher.doFinal(tmp,(short)0,lc,buf,(short)0);
                  apdu.setOutgoingLength(outLength);
                  apdu.sendBytes((short)0,outLength);
                  break;
               case INS_DECRYPT:
                  readBuffer(apdu,tmp,(short)0,lc);
                  apdu.setOutgoing();
                  cipher.init(privKey,Cipher.MODE_DECRYPT);
                  outLength = cipher.doFinal(tmp,(short)0,lc,buf,(short)0);
                  apdu.setOutgoingLength(outLength);
                  apdu.sendBytes((short)0,outLength);
                  break;
               default:
                  ISOException.throwIt(SW_INS_NOT_SUPPORTED);
            }
            break;
         default:
            ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
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
   private void readBuffer(APDU apdu, byte[] dest, short offset,
                           short length) {
      byte[] buf = apdu.getBuffer();
      short readCount = apdu.setIncomingAndReceive();
      short i = 0;
      Util.arrayCopy(buf,OFFSET_CDATA,dest,offset,readCount);
      while ((short)(i + readCount) < length) {
         i += readCount;
         offset += readCount;
         readCount = (short)apdu.receiveBytes(OFFSET_CDATA);
         Util.arrayCopy(buf,OFFSET_CDATA,dest,offset,readCount);
      }
   }
}

