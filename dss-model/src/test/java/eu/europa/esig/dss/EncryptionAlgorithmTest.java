package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class EncryptionAlgorithmTest {

	@Test
	public void forName() {
		assertEquals(EncryptionAlgorithm.RSA, EncryptionAlgorithm.forName(EncryptionAlgorithm.RSA.getName()));
	}

	@Test(expected = DSSException.class)
	public void forNameException() {
		EncryptionAlgorithm.forName("aaa");
	}

	@Test
	public void forNameSubstitution() {
		assertEquals(EncryptionAlgorithm.RSA, EncryptionAlgorithm.forName("aaa", EncryptionAlgorithm.RSA));
	}

	@Test
	public void forNameECDSA() {
		assertEquals(EncryptionAlgorithm.ECDSA, EncryptionAlgorithm.forName("EC"));
		assertEquals(EncryptionAlgorithm.ECDSA, EncryptionAlgorithm.forName("ECC"));
	}

	@Test
	public void forOID() {
		assertEquals(EncryptionAlgorithm.RSA, EncryptionAlgorithm.forOID(EncryptionAlgorithm.RSA.getOid()));
	}

	@Test(expected = DSSException.class)
	public void forOIDException() {
		EncryptionAlgorithm.forOID("aaa");
	}

}
