package eu.europa.esig.trustedlist;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import org.junit.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

public class TrustedListFacadeTest {

	@Test
	public void testTL() throws JAXBException, XMLStreamException, IOException, SAXException {
		marshallUnmarshall(new File("src/test/resources/tl.xml"));
	}

	@Test
	public void testLOTL() throws JAXBException, XMLStreamException, IOException, SAXException {
		marshallUnmarshall(new File("src/test/resources/lotl.xml"));
	}

	private void marshallUnmarshall(File file) throws JAXBException, XMLStreamException, IOException, SAXException {
		TrustedListFacade facade = TrustedListFacade.newFacade();

		TrustStatusListType trustStatusListType = facade.unmarshall(file);
		assertNotNull(trustStatusListType);

		String marshall = facade.marshall(trustStatusListType, true);
		assertNotNull(marshall);
	}

}
