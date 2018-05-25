package eu.europa.esig.dss.token.mocca;

import java.security.KeyStore.PasswordProtection;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.PrefilledPasswordCallback;

public class MOCCASignatureTokenConnectionApp {

	private static final String PIN_CODE = "PINCODE";

	public static void main(String[] args) {
		try (MOCCASignatureTokenConnection token = new MOCCASignatureTokenConnection(
				new PrefilledPasswordCallback(new PasswordProtection(PIN_CODE.toCharArray())))) {

			List<DSSPrivateKeyEntry> keys = token.getKeys();
			for (DSSPrivateKeyEntry entry : keys) {
				System.out.println(entry.getCertificate().getCertificate());
			}

			ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes());
			SignatureValue signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA1, keys.get(0));
			System.out.println("Signature value : " + Base64.toBase64String(signatureValue.getValue()));
		}
	}

}
