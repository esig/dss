package eu.europa.esig.dss.token;

import java.util.List;

import javax.xml.bind.DatatypeConverter;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

public class PKCS11SignatureTokenApp {

	public static void main(String[] args) {

		Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\System32\\beidpkcs11.dll");

		List<DSSPrivateKeyEntry> keys = token.getKeys();
		for (DSSPrivateKeyEntry entry : keys) {
			System.out.println(entry.getCertificate().getCertificate());
		}

		ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
		SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, keys.get(0));
		System.out.println("Signature value : " + DatatypeConverter.printBase64Binary(signatureValue.getValue()));
	}

}
