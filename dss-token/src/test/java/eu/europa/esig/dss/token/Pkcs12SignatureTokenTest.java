package eu.europa.esig.dss.token;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.KeyStore.PasswordProtection;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

public class Pkcs12SignatureTokenTest {

	@Test
	public void testPkcs12() throws IOException {
		try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/user_a_rsa.p12",
				new PasswordProtection("password".toCharArray()))) {
			assertNotNull(signatureToken);

			List<DSSPrivateKeyEntry> keys = signatureToken.getKeys();
			assertFalse(keys.isEmpty());

			KSPrivateKeyEntry dssPrivateKeyEntry = (KSPrivateKeyEntry) keys.get(0);
			assertNotNull(dssPrivateKeyEntry);
			assertNotNull(dssPrivateKeyEntry.getAlias());

			DSSPrivateKeyEntry entry = signatureToken.getKey(dssPrivateKeyEntry.getAlias(), new PasswordProtection("password".toCharArray()));
			assertNotNull(entry);
			assertNotNull(entry.getCertificate());
			assertNotNull(entry.getCertificateChain());
			assertNotNull(entry.getEncryptionAlgorithm());

			ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes("UTF-8"));
			SignatureValue signValue = signatureToken.sign(toBeSigned, DigestAlgorithm.SHA256, entry);
			assertNotNull(signValue);
			assertNotNull(signValue.getAlgorithm());
			assertNotNull(signValue.getValue());
		}
	}

	@Test(expected = DSSException.class)
	public void wrongPassword() throws IOException {
		try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/user_a_rsa.p12",
				new PasswordProtection("wrong password".toCharArray()))) {

		}
	}

}
