package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class DigestAlgorithmTest {

	@Test
	public void forOid() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forOID(DigestAlgorithm.SHA256.getOid()));
	}

	@Test(expected = DSSException.class)
	public void forOidException() {
		DigestAlgorithm.forOID("aaa");
	}

	@Test
	public void forXML() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forXML(DigestAlgorithm.SHA256.getXmlId()));
	}

	@Test(expected = DSSException.class)
	public void forXMLException() {
		DigestAlgorithm.forXML("aaa");
	}

	@Test
	public void forXMLSubstitution() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forXML("aaa", DigestAlgorithm.SHA256));
	}

	@Test
	public void forName() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forName(DigestAlgorithm.SHA256.getName()));
	}

	@Test(expected = DSSException.class)
	public void forNameException() {
		DigestAlgorithm.forName("aaa");
	}

	@Test
	public void forNameSubstitution() {
		assertEquals(DigestAlgorithm.SHA256, DigestAlgorithm.forName("aaa", DigestAlgorithm.SHA256));
	}

}
