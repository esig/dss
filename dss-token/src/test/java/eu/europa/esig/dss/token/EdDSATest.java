package eu.europa.esig.dss.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.spi.DSSSecurityProvider;

public class EdDSATest {

	@Test
	public void ed25519() throws GeneralSecurityException {

		Security.addProvider(DSSSecurityProvider.getSecurityProvider());

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", DSSSecurityProvider.getSecurityProviderName());
		KeyPair kp = kpg.generateKeyPair();
		assertNotNull(kp);

		PublicKey publicKey = kp.getPublic();
		assertNotNull(publicKey);
		assertEquals("Ed25519", publicKey.getAlgorithm());
		assertEquals(EncryptionAlgorithm.ED25519, EncryptionAlgorithm.forKey(publicKey));

		PrivateKey privateKey = kp.getPrivate();
		assertNotNull(privateKey);
		assertEquals("Ed25519", privateKey.getAlgorithm());
	}

	@Test
	public void ed448() throws GeneralSecurityException {

		Security.addProvider(DSSSecurityProvider.getSecurityProvider());

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed448", DSSSecurityProvider.getSecurityProviderName());
		KeyPair kp = kpg.generateKeyPair();
		assertNotNull(kp);

		PublicKey publicKey = kp.getPublic();
		assertNotNull(publicKey);
		assertEquals("Ed448", publicKey.getAlgorithm());
		assertEquals(EncryptionAlgorithm.ED448, EncryptionAlgorithm.forKey(publicKey));

		PrivateKey privateKey = kp.getPrivate();
		assertNotNull(privateKey);
		assertEquals("Ed448", privateKey.getAlgorithm());
	}

}
