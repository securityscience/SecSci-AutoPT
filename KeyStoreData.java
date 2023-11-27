/* ---------------------------------------
   Sec-Sci AutoPT v3.2311 - January 2018
   ---------------------------------------
   Site:      www.security-science.com
   Email:     RnD@security-science.com
   Creator:   ARNEL C. REYES
   @license:  GNU GPL 3.0
   @copyright (C) 2018 WWW.SECURITY-SCIENCE.COM
*/

import java.io.FileInputStream;
import java.security.KeyStore;

public class KeyStoreData {
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java KeyStoreData <keystorePath> <keystorePassword> <keyAlias>");
            System.exit(1);
        }

        String keystorePath = args[0];
        String keystorePassword = args[1];
        String keyAlias = args[2];

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream(keystorePath);
            keyStore.load(fis, keystorePassword.toCharArray());

            // Retrieve the secret value
            byte[] secretValueBytes = ((KeyStore.SecretKeyEntry) keyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(keystorePassword.toCharArray()))).getSecretKey().getEncoded();
            String secretValue = new String(secretValueBytes);
            System.out.println(secretValue);
        } catch (java.security.UnrecoverableKeyException e) {
            System.out.println("Error: Unable to recover the key. Check if the keystore password or key alias is correct.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
