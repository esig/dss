package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.AppleSignatureToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

public class AppleKeychainSnippet {

    public static void main(String[] args) {

        // tag::demo[]

        try (AppleSignatureToken token = new AppleSignatureToken()) {

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
