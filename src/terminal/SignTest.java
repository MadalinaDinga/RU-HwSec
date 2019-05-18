package terminal;

import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class SignTest {

    public static void main(String args[]) throws Exception {

        Security.insertProviderAt(new BouncyCastleProvider(), 1);


        System.out.println("Starting");
        Signature sig = Signature.getInstance("SHA1withRSA/PSS");
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        byte[] data = {'H', 'E', 'L', 'L', 'O'};

        sig.initSign(kp.getPrivate());
        sig.update(data);
        byte[] signature = sig.sign();

        System.out.println("Signature" + signature);

        sig.initVerify(kp.getPublic());
        sig.update(data);
        if (sig.verify(signature)) {
            System.out.println("Verified!");
        } else {
            System.err.println("Failed to verify signature");
        }


    }



}