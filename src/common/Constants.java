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
    public static final byte INS_VERIFY = (byte) 0x09;
    public static final short CERTIFICATE_LENGTH = 128;
    
    /** Number of bytes to use a challenge */
    public static final short CHALLENGE_LENGTH = 2;

	public static final byte START_AUTHENTICATION_PROTOCOL = 0x0a;
	public static final byte START_RELOAD_PROTOCOL = 0x0b;
    public static final byte START_PAYMENT_PROTOCOL = 0x0c;
    
    /*
     *          REASONS
     */
    public static final short SW_CERTIFICATE_CHECK_FAILED = (short) 0x000A;
    public static final short SW_CHALLENGE_FAILED = (short) 0x000B;
    public static final byte[] CHALLENGE_TAG = new byte[] {(byte) 0, (byte) 1, (byte) 0, (byte) 1};
    public static final short CHALLENGE_TAG_LENGTH = (short) CHALLENGE_TAG.length;
    public static final short SW_INVALID_AMOUNT = (short) 0x000C;
    public static final short SW_INSUFFICIENT_BALANCE = (short) 0x000D;
    public static final short SW_WRONG_PIN = (short) 0x000E;
    public static final short SW_BLOCKED = (short) 0x000F;



}