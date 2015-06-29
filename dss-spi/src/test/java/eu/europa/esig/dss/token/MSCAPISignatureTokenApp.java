package eu.europa.esig.dss.token;

import java.util.List;

import org.apache.commons.codec.binary.Base64;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

public class MSCAPISignatureTokenApp {

	public static void main(String[] args){

		MSCAPISignatureToken token = new MSCAPISignatureToken(null);

		List<DSSPrivateKeyEntry> keys = token.getKeys();
		for (DSSPrivateKeyEntry entry : keys) {
			System.out.println(entry.getCertificate().getCertificate());
		}

		ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
		SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, keys.get(0));

		System.out.println("Signature value : " + Base64.encodeBase64String(signatureValue.getValue()));
	}

}
