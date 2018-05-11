package eu.europa.esig.dss.xades;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.StringReader;

import javax.xml.transform.stream.StreamSource;

import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.utils.Utils;

public class DSSXMLUtilsTest {

	@Test
	public void isOid() {
		assertFalse(DSSXMLUtils.isOid(null));
		assertFalse(DSSXMLUtils.isOid(""));
		assertFalse(DSSXMLUtils.isOid("aurn:oid:1.2.3.4"));
		assertTrue(DSSXMLUtils.isOid("urn:oid:1.2.3.4"));
		assertTrue(DSSXMLUtils.isOid("URN:OID:1.2.3.4"));
	}

	@Test
	public void validateAgainstXSD() throws SAXException {
		DSSXMLUtils.validateAgainstXSD(new FileDocument("src/test/resources/valid-xades-structure.xml"));
	}

	@Test(expected = SAXException.class)
	public void validateAgainstXSDInvalid() throws SAXException {
		DSSXMLUtils.validateAgainstXSD(new FileDocument("src/test/resources/invalid-xades-structure.xml"));
	}

	@Test
	public void validateAgainstXSDvalidMessage() {
		FileDocument document = new FileDocument("src/test/resources/valid-xades-structure.xml");
		Document dom = DomUtils.buildDOM(document);
		String xmlToString = DomUtils.xmlToString(dom.getDocumentElement());
		assertFalse(Utils.isStringNotEmpty(DSSXMLUtils.validateAgainstXSD(new StreamSource(new StringReader(xmlToString)))));
	}

	@Test
	public void validateAgainstXSDInvalidMessage() {
		FileDocument document = new FileDocument("src/test/resources/invalid-xades-structure.xml");
		Document dom = DomUtils.buildDOM(document);
		String xmlToString = DomUtils.xmlToString(dom.getDocumentElement());
		assertTrue(Utils.isStringNotEmpty(DSSXMLUtils.validateAgainstXSD(new StreamSource(new StringReader(xmlToString)))));
	}

}
