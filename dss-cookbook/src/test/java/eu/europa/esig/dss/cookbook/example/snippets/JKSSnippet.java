package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.JKSSignatureToken;
import eu.europa.esig.dss.utils.Utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore.PasswordProtection;
import java.util.List;

public class JKSSnippet {

    public static void main(String[] args) throws IOException {

        // tag::demo[]

        try (InputStream is = new FileInputStream("src/main/resources/keystore.jks");
             JKSSignatureToken token = new JKSSignatureToken(is, new PasswordProtection("dss-password".toCharArray()))) {

            List<DSSPrivateKeyEntry> keys = token.getKeys();
            for (DSSPrivateKeyEntry entry : keys) {
                System.out.println(entry.getCertificate().getCertificate());
            }

            ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
            SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, keys.get(0));

            System.out.println("Signature value : " + Utils.toBase64(signatureValue.getValue()));
        }

        // end::demo[]
    }

}
