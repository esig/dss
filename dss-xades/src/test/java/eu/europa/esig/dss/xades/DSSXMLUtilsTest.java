package eu.europa.esig.dss.xades;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class DSSXMLUtilsTest {

	@Test
	public void isOid() {
		assertFalse(DSSXMLUtils.isOid(null));
		assertFalse(DSSXMLUtils.isOid(""));
		assertFalse(DSSXMLUtils.isOid("aurn:oid:1.2.3.4"));
		assertTrue(DSSXMLUtils.isOid("urn:oid:1.2.3.4"));
		assertTrue(DSSXMLUtils.isOid("URN:OID:1.2.3.4"));
	}

}
