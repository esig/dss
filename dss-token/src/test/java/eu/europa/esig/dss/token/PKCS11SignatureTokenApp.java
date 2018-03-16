package eu.europa.esig.dss.token;

import java.util.List;

import javax.xml.bind.DatatypeConverter;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

public class PKCS11SignatureTokenApp {

	public static void main(String[] args) {
		System.setProperty("java.security.debug", "sunpkcs11");

		// 32b
		// Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\SysWOW64\\onepin-opensc-pkcs11.dll");

		// 64b
		// Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\System32\\onepin-opensc-pkcs11.dll");
		// Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\System32\\beidpkcs11.dll");
		Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\System32\\beidpkcs11.dll", (PasswordInputCallback) null, 1);

		List<DSSPrivateKeyEntry> keys = token.getKeys();
		for (DSSPrivateKeyEntry entry : keys) {
			System.out.println(entry.getCertificate().getCertificate());
		}

		ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
		SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, keys.get(0));
		System.out.println("Signature value : " + DatatypeConverter.printBase64Binary(signatureValue.getValue()));
	}

}
