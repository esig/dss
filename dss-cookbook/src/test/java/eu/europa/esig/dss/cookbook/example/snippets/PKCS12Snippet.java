package eu.europa.esig.dss.cookbook.example.snippets;

import java.io.IOException;
import java.util.List;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.utils.Utils;

public class PKCS12Snippet {

	public static void main(String[] args) throws IOException {

		// tag::demo[]

		SignatureTokenConnection token = new Pkcs12SignatureToken("src/main/resources/user_a_rsa.p12", "password");

		List<DSSPrivateKeyEntry> keys = token.getKeys();
		for (DSSPrivateKeyEntry entry : keys) {
			System.out.println(entry.getCertificate().getCertificate());
		}

		ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
		SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, keys.get(0));

		System.out.println("Signature value : " + Utils.toBase64(signatureValue.getValue()));

		// end::demo[]

	}

}
