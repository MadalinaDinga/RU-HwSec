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
    public static final byte START_PIN_RESET_PROTOCOL = 0x0d;
    
    /*
     *          REASONS
     */
    public static final short SW_CERTIFICATE_CHECK_FAILED = (short) 0x900A;
    public static final short SW_CHALLENGE_FAILED = (short) 0x900B;



}