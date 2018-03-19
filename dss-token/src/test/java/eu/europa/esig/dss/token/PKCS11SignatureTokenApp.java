package eu.europa.esig.dss.token;

import java.security.KeyStore.PasswordProtection;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

public class PKCS11SignatureTokenApp {

	public static void main(String[] args) {

		String PIN = "PINCODE";

		// -Djava.security.debug = sunpkcs11

		// 32b
		// Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\SysWOW64\\onepin-opensc-pkcs11.dll");

		// 64b
		// Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\System32\\beidpkcs11.dll");
		// Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\System32\\beidpkcs11.dll",
		// (PasswordInputCallback) null, 3)

		// Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Windows\\System32\\onepin-opensc-pkcs11.dll",
		// new PasswordProtection(PIN.toCharArray()), 1)
		String alias = null;
		try (Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Program Files\\Gemalto\\Classic Client\\BIN\\gclib.dll",
				new PasswordProtection(PIN.toCharArray()), 2)) {

			List<DSSPrivateKeyEntry> keys = token.getKeys();
			for (DSSPrivateKeyEntry entry : keys) {
				System.out.println(entry.getCertificate().getCertificate());
			}

			alias = ((KSPrivateKeyEntry) keys.get(0)).getAlias();

			// ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
			// SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, dssPrivateKeyEntry);
			// System.out.println("Signature value : " +
			// DatatypeConverter.printBase64Binary(signatureValue.getValue()));
		}

		try (Pkcs11SignatureToken token = new Pkcs11SignatureToken("C:\\Program Files\\Gemalto\\Classic Client\\BIN\\gclib.dll",
				new PasswordProtection(PIN.toCharArray()), 2)) {

			DSSPrivateKeyEntry key = token.getKey(alias, new PasswordProtection(PIN.toCharArray()));

			ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
			SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, key);
			System.out.println("Signature value : " + DatatypeConverter.printBase64Binary(signatureValue.getValue()));
		}
	}

}
