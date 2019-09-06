package eu.europa.esig.trustedlist;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import javax.xml.bind.JAXBException;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

public class TrustedListUtilsTest {

	@Test
	public void getJAXBContext() throws JAXBException {
		assertNotNull(TrustedListUtils.getJAXBContext());
		// cached
		assertNotNull(TrustedListUtils.getJAXBContext());
	}

	@Test
	public void getSchema() throws SAXException {
		assertNotNull(TrustedListUtils.getSchema());
		// cached
		assertNotNull(TrustedListUtils.getSchema());
	}

}
