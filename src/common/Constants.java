package common;

public class Constants {

    public static final byte[] APPLET_AID = { (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x90, (byte) 0xAB };

    /* 
     *          Personalization commands
     */
    /** Send public exponent command */
    public static final byte INS_PUBLIC_EXPONENT = (byte) 0x03;
    /** Send public modulus command */
    public static final byte INS_PUBLIC_MODULUS = (byte) 0x04;
    /** Receive certificate */
    public static final byte INS_STORE_KEY_CERTIFICATE = (byte) 0x05;
    /** Receive master key modulus/exponent */
    public static final byte INS_STORE_MASTER_KEY = (byte) 0x06;
    /** Issue card command */
    public static final byte INS_ISSUE = (byte) 0x07;
    
    public static final short CERTIFICATE_LENGTH = 128;
    
    /** Number of bytes to use a challenge */
    public static final short CHALLENGE_LENGTH = 2;
    /** Signing tag */
    public static final byte[] CHALLENGE_TAG = new byte[] {(byte) 0, (byte) 1, (byte) 0, (byte) 1};
    public static final short CHALLENGE_TAG_LENGTH = (short) CHALLENGE_TAG.length;

    /**
     *          Initialize protocols
     */
    /** Start authentication protocol */
    public static final byte START_AUTHENTICATION_PROTOCOL = 0x0a;
    /** Start reload protocol */
    public static final byte START_RELOAD_PROTOCOL = 0x0b;
    /** Start payment protocol */
    public static final byte START_PAYMENT_PROTOCOL = 0x0c;
    
    /*
     *         REASONS for failure
     */
    public static final short SW_CERTIFICATE_CHECK_FAILED = (short) 0x000A;
    public static final short SW_CHALLENGE_FAILED = (short) 0x000B;
    public static final short SW_INVALID_AMOUNT = (short) 0x000C;
    public static final short SW_INSUFFICIENT_BALANCE = (short) 0x000D;
    public static final short SW_WRONG_PIN = (short) 0x000E;
    public static final short SW_BLOCKED = (short) 0x000F;
    public static final short SW_WRONG_FORMAT = (short) 0x009;
    public static final short SW_RESET_PIN = (short) 0x008;
    public static final byte[] PIN_TAG = new byte[] {0, 1, 0, 2};
    public static final byte[] PAYMENT_TAG = new byte[] {0, 1, 0, 3};
    public static final byte[] RELOAD_TAG = new byte[] {0, 1, 0, 4};


}