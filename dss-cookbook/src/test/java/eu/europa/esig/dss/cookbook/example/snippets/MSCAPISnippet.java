package eu.europa.esig.dss.cookbook.example.snippets;

import java.util.List;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.utils.Utils;

public class MSCAPISnippet {

	public static void main(String[] args) {

		// tag::demo[]

		try (MSCAPISignatureToken token = new MSCAPISignatureToken()) {

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
