package terminal;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.math.BigInteger;
import java.util.List;
import javax.swing.*;

import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;

import javax.smartcardio.*;

/**
 * Sample terminal for the Crypto applet.
 * 
 * @author Martijn Oostdijk (martijno@cs.kun.nl)
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 * 
 * @version $Revision: 2.0 $
 */
public class CryptoTerminal extends JPanel implements ActionListener {
	static final int BLOCKSIZE = 128;

	static final String TITLE = "Crypto Terminal";
	static final int DISPLAY_WIDTH = 30;
	static final int DISPLAY_HEIGHT = 20;

	static final String MSG_ERROR = "Error";
	static final String MSG_INVALID = "Invalid";

	static final byte[] APPLET_AID = { (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x90, (byte) 0xAB };
	static final byte CLA_ISO = (byte) 0x00;
	static final byte INS_SELECT = (byte) 0xA4;
	static final short SW_NO_ERROR = (short) 0x9000;
	static final short SW_APPLET_SELECT_FAILED = (short) 0x6999;
	static final short SW_FILE_NOT_FOUND = (short) 0x6A82;

	static final CommandAPDU SELECT_APDU = new CommandAPDU((byte) 0x00,
			(byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID);

	private static final byte CLA_CRYPTO = (byte) 0xCC;
	private static final byte INS_SET_PUB_MODULUS = (byte) 0x02;
	private static final byte INS_SET_PRIV_MODULUS = (byte) 0x12;
	private static final byte INS_SET_PRIV_EXP = (byte) 0x22;
	private static final byte INS_SET_PUB_EXP = (byte) 0x32;
	private static final byte INS_ISSUE = (byte) 0x40;
	private static final byte INS_ENCRYPT = (byte) 0xE0;
	private static final byte INS_DECRYPT = (byte) 0xD0;

	private static final int STATE_INIT = 0;
	private static final int STATE_ISSUED = 1;

	/** GUI stuff. */
	JTextArea display;

	/** GUI stuff. */
	JButton setPubKeyButton, setPrivKeyButton, issueButton, encryptButton,
			decryptButton;

	/** File browser needs to remember last dir it accessed. */
	File currentDir = new File(".");

	/** The card applet. */
	CardChannel applet;

	/**
	 * Constructs the terminal application.
	 */
	public CryptoTerminal() {
		buildGUI();
		setEnabled(false);
		addActionListener(this);
		(new CardThread()).start();
	}

	/**
	 * Builds the GUI.
	 */
	void buildGUI() {
		setLayout(new BorderLayout());
		display = new JTextArea(DISPLAY_HEIGHT, DISPLAY_WIDTH);
		display.setEditable(false);
		add(new JScrollPane(display), BorderLayout.CENTER);
		JPanel buttons = new JPanel(new FlowLayout());
		setPubKeyButton = new JButton("Set Pub");
		setPrivKeyButton = new JButton("Set Priv");
		issueButton = new JButton("Issue");
		encryptButton = new JButton("Encrypt");
		decryptButton = new JButton("Decrypt");
		buttons.add(setPubKeyButton);
		buttons.add(setPrivKeyButton);
		buttons.add(issueButton);
		buttons.add(encryptButton);
		buttons.add(decryptButton);
		add(buttons, BorderLayout.SOUTH);
	}

	/**
	 * Enables/disables the buttons.
	 * 
	 * @param b
	 *            boolean indicating whether to enable or disable the buttons.
	 */
	public void setEnabled(boolean b) {
		super.setEnabled(b);
		setPubKeyButton.setEnabled(b);
		setPrivKeyButton.setEnabled(b);
		issueButton.setEnabled(b);
		encryptButton.setEnabled(b);
		decryptButton.setEnabled(b);
	}

	/**
	 * Adds the action listener <code>l</code> to all buttons.
	 * 
	 * @param l
	 *            the action listener to add.
	 */
	public void addActionListener(ActionListener l) {
		setPubKeyButton.addActionListener(l);
		setPrivKeyButton.addActionListener(l);
		issueButton.addActionListener(l);
		encryptButton.addActionListener(l);
		decryptButton.addActionListener(l);
	}

	class CardThread extends Thread {
		public void run() {
			try {
				TerminalFactory tf = TerminalFactory.getDefault();
				CardTerminals ct = tf.terminals();
				List<CardTerminal> cs = ct
						.list(CardTerminals.State.CARD_PRESENT);
				if (cs.isEmpty()) {
					log("No terminals with a card found.");
					return;
				}

				while (true) {
					try {
						for (CardTerminal c : cs) {
							if (c.isCardPresent()) {
								try {
									Card card = c.connect("*");
									try {
										applet = card.getBasicChannel();
										ResponseAPDU resp = applet
												.transmit(SELECT_APDU);
										if (resp.getSW() != 0x9000) {
											throw new Exception("Select failed");
										}
										setEnabled(true);

										// Wait for the card to be removed
										while (c.isCardPresent())
											;
										setEnabled(false);
										break;
									} catch (Exception e) {
										log("Card does not contain CryptoApplet?!");
										sleep(2000);
										continue;
									}
								} catch (CardException e) {
									log("Couldn't connect to card!");
									sleep(2000);
									continue;
								}
							} else {
								log("No card present!");
								sleep(2000);
								continue;
							}
						}
					} catch (CardException e) {
						log("Card status problem!");
					}
				}
			} catch (Exception e) {
				setEnabled(false);
				log("ERROR: " + e.getMessage());
				e.printStackTrace();
			}
		}
	}

	/**
	 * Handles button events.
	 * 
	 * @param ae
	 *            event indicating a button was pressed.
	 */
	public void actionPerformed(ActionEvent ae) {
		try {
			Object src = ae.getSource();
			if (src instanceof JButton) {
				JButton button = (JButton) src;
				if (button.equals(setPubKeyButton)) {
					setPubKey();
				} else if (button.equals(setPrivKeyButton)) {
					setPrivKey();
				} else if (button.equals(issueButton)) {
					issue();
				} else if (button.equals(encryptButton)) {
					encrypt();
				} else if (button.equals(decryptButton)) {
					decrypt();
				}
			}
		} catch (Exception e) {
			System.out.println("ERROR: " + e.getMessage());
		}
	}

	/**
	 * Handles 'set pub key' button event.
	 * 
	 * @throws CardException
	 *             if something goes wrong.
	 */
	void setPubKey() throws CardException {
		try {
			byte[] data = readFile();
			X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			RSAPublicKey key = (RSAPublicKey) factory.generatePublic(spec);

			byte[] modulus = getBytes(key.getModulus());

			CommandAPDU capdu;
			capdu = new CommandAPDU(CLA_CRYPTO, INS_SET_PUB_MODULUS, (byte) 0,
					(byte) 0, modulus);
			sendCommandAPDU(capdu);

			byte[] exponent = getBytes(key.getPublicExponent());
			capdu = new CommandAPDU(CLA_CRYPTO, INS_SET_PUB_EXP, (byte) 0,
					(byte) 0, exponent);
			sendCommandAPDU(capdu);
		} catch (Exception e) {
			throw new CardException(e.getMessage());
		}
	}

	/**
	 * Handles 'set priv key' button event.
	 * 
	 * @throws CardException
	 *             if something goes wrong.
	 */
	void setPrivKey() throws CardException {
		try {
			byte[] data = readFile();
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(data);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			RSAPrivateKey key = (RSAPrivateKey) factory.generatePrivate(spec);

			byte[] modulus = getBytes(key.getModulus());
			CommandAPDU capdu;
			capdu = new CommandAPDU(CLA_CRYPTO, INS_SET_PRIV_MODULUS, (byte) 0,
					(byte) 0, modulus);
			sendCommandAPDU(capdu);

			byte[] exponent = getBytes(key.getPrivateExponent());
			capdu = new CommandAPDU(CLA_CRYPTO, INS_SET_PRIV_EXP, (byte) 0,
					(byte) 0, exponent);
			sendCommandAPDU(capdu);

		} catch (Exception e) {
			throw new CardException(e.getMessage());
		}
	}

	/**
	 * Handles 'issue' button event.
	 * 
	 * @throws CardException
	 *             if something goes wrong.
	 */
	void issue() throws CardException {
		try {
			CommandAPDU capdu = new CommandAPDU(CLA_CRYPTO, INS_ISSUE,
					(byte) 0, (byte) 0);
			sendCommandAPDU(capdu);
		} catch (Exception e) {
			throw new CardException(e.getMessage());
		}
	}

	/**
	 * Handles 'encrypt' button event.
	 * 
	 * @throws CardException
	 *             if something goes wrong.
	 */
	void encrypt() throws CardException {
		try {
			byte[] data = readFile();
			if (data.length > BLOCKSIZE) {
				throw new CardException("File too large.");
			}
			CommandAPDU capdu = new CommandAPDU(CLA_CRYPTO, INS_ENCRYPT,
					(byte) 0, (byte) 0, data, BLOCKSIZE);
			ResponseAPDU rapdu = sendCommandAPDU(capdu);
			log(rapdu);
		} catch (IOException e) {
			throw new CardException(e.getMessage());
		}
	}

	/**
	 * Handles 'decrypt' button event.
	 * 
	 * @throws CardException
	 *             if something goes wrong.
	 */
	void decrypt() throws Exception {
		try {
			byte[] data = readFile();
			if (data.length > BLOCKSIZE) {
				throw new Exception("File too large.");
			}
			CommandAPDU capdu = new CommandAPDU(CLA_CRYPTO, INS_DECRYPT,
					(byte) 0, (byte) 0, data, BLOCKSIZE);
			applet.transmit(capdu);
		} catch (IOException e) {
			throw new Exception(e.getMessage());
		}
	}

	/**
	 * Sends a command to the card.
	 * 
	 * @param capdu
	 *            the command to send.
	 * 
	 * @return the response from the card.
	 * 
	 * @throws CardTerminalException
	 *             if something goes wrong.
	 */
	ResponseAPDU sendCommandAPDU(CommandAPDU capdu)
			throws CardException {
		log(capdu);
		ResponseAPDU rapdu = applet.transmit(capdu);
		log(rapdu);
		return rapdu;
	}

	String toHexString(byte[] in) {
		StringBuilder out = new StringBuilder(2*in.length);
		for(int i = 0; i < in.length; i++) {
			out.append(String.format("%02x ", (in[i] & 0xFF)));
		}
		return out.toString().toUpperCase();
	}
	
	/**
	 * Writes <code>obj</code> to the log.
	 * 
	 * @param obj
	 *            the message to write to the log.
	 */
	void log(ResponseAPDU obj) {
		display.append(obj.toString() + ", Data=" + toHexString(obj.getData()) + "\n");
		System.out.println(obj.toString());
	}

	/**
	 * Writes <code>obj</code> to the log.
	 * 
	 * @param obj
	 *            the message to write to the log.
	 */
	void log(CommandAPDU obj) {
		display.append(obj.toString() + ", Data=" + toHexString(obj.getData()) + "\n");
		System.out.println(obj.toString());
	}

	/**
	 * Writes <code>obj</code> to the log.
	 * 
	 * @param obj
	 *            the message to write to the log.
	 */
	void log(Object obj) {
		display.append(obj.toString() + "\n");
		System.out.println(obj.toString());
	}

	/**
	 * Pops up dialog to ask user to select file and reads the file.
	 * 
	 * @return byte array with contents of the file.
	 * 
	 * @throws IOException
	 *             if file could not be read.
	 */
	byte[] readFile() throws IOException {
		JFileChooser chooser = new JFileChooser();
		chooser.setCurrentDirectory(currentDir);
		int n = chooser.showOpenDialog(this);
		if (n != JFileChooser.APPROVE_OPTION) {
			throw new IOException("No file selected");
		}
		File file = chooser.getSelectedFile();
		FileInputStream in = new FileInputStream(file);
		int length = in.available();
		byte[] data = new byte[length];
		in.read(data);
		in.close();
		currentDir = file.getParentFile();
		return data;
	}

	/**
	 * Gets an unsigned byte array representation of <code>big</code>. A leading
	 * zero (present only to hold sign bit) is stripped.
	 * 
	 * @param big
	 *            a big integer.
	 * 
	 * @return a byte array containing a representation of <code>big</code>.
	 */
	byte[] getBytes(BigInteger big) {
		byte[] data = big.toByteArray();
		if (data[0] == 0) {
			byte[] tmp = data;
			data = new byte[tmp.length - 1];
			System.arraycopy(tmp, 1, data, 0, tmp.length - 1);
		}
		return data;
	}

	/**
	 * Creates an instance of this class and puts it inside a frame.
	 * 
	 * @param arg
	 *            command line arguments.
	 */
	public static void main(String[] arg) {
		JFrame frame = new JFrame(TITLE);
		Container c = frame.getContentPane();
		CryptoTerminal panel = new CryptoTerminal();
		c.add(panel);
		frame.addWindowListener(new CloseEventListener());
		frame.pack();
		frame.setVisible(true);
	}
}

/**
 * Class to close window.
 */
class CloseEventListener extends WindowAdapter {
	/**
	 * What to do when user closes window.
	 * 
	 * @param we
	 *            window event.
	 */
	public void windowClosing(WindowEvent we) {
		System.exit(0);
	}
}
