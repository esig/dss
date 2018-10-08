package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class SignatureAlgorithmTest {

	@Test
	public void forXML() {
		assertEquals(SignatureAlgorithm.RSA_SHA512, SignatureAlgorithm.forXML(SignatureAlgorithm.RSA_SHA512.getXMLId()));
	}

	@Test(expected = DSSException.class)
	public void forXMLException() {
		SignatureAlgorithm.forXML("aaa");
	}

	@Test
	public void forXMLSubstitution() {
		assertEquals(SignatureAlgorithm.RSA_SHA512, SignatureAlgorithm.forXML("aaa", SignatureAlgorithm.RSA_SHA512));
	}

	@Test
	public void forOid() {
		assertEquals(SignatureAlgorithm.RSA_SHA512, SignatureAlgorithm.forOID("1.2.840.113549.1.1.13"));
	}

	@Test(expected = DSSException.class)
	public void forOidException() {
		SignatureAlgorithm.forOID("1.2.3");
	}

}
