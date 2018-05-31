package eu.europa.esig.dss.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.KeyStore.PasswordProtection;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

public class RemoteSignatureTokenConnectionImplTest {

	@Test
	public void testRemoteSigning() throws IOException {

		Pkcs12SignatureToken serverToken = new Pkcs12SignatureToken("src/test/resources/good-user.p12",
				new PasswordProtection("ks-password".toCharArray()));
		
		RemoteSignatureTokenConnectionImpl exposedToken = new RemoteSignatureTokenConnectionImpl();
		exposedToken.setToken(serverToken);
		
		List<RemoteKeyEntry> keys = exposedToken.getKeys();
		assertTrue(keys != null && keys.size() > 0);

		for (RemoteKeyEntry remoteKeyEntry : keys) {
			assertNotNull(remoteKeyEntry.getAlias());
			assertNotNull(remoteKeyEntry.getCertificate());
			assertNotNull(remoteKeyEntry.getCertificateChain());

			RemoteKeyEntry key = exposedToken.getKey(remoteKeyEntry.getAlias());
			assertEquals(remoteKeyEntry.getAlias(), key.getAlias());
			assertEquals(remoteKeyEntry.getEncryptionAlgo(), key.getEncryptionAlgo());
		}
		
		RemoteKeyEntry remoteKeyEntry = keys.get(0);
		ToBeSigned toBeSigned = new ToBeSigned(new byte[] {1,2,3,4,5});
		SignatureValue signatureValue = exposedToken.sign(toBeSigned, DigestAlgorithm.SHA256,
				remoteKeyEntry.getAlias());
		assertNotNull(signatureValue);
		assertNotNull(signatureValue.getValue());
		assertEquals(SignatureAlgorithm.RSA_SHA256, signatureValue.getAlgorithm());
	}

}
