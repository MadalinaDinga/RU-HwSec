package common;

public class Constants {

    public static final byte[] APPLET_AID = { (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x90, (byte) 0xAB };

    /* 
     *          Personalization commands
     */
    public static final byte INS_PUBLIC_EXPONENT = (byte) 0x03;
    public static final byte INS_PUBLIC_MODULUS = (byte) 0x04;
    public static final byte INS_STORE_KEY_CERTIFICATE = (byte) 0x05;
    public static final byte INS_STORE_MASTER_KEY = (byte) 0x06;
    public static final byte INS_ISSUE = (byte) 0x07;

    public static final byte INS_KEY_CERTIFICATE = (byte) 0x08;

	public static final short CERTIFICATE_LENGTH = 128;



}