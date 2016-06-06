package eu.europa.esig.dss.xades;

import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;

public class DSSXMLUtilsTest {

	private static final String XML_HEADER = "<?xml version='1.0' encoding='UTF-8'?>";
	private static final String XML_TEXT = "<hello><world></world></hello>";

	private static final String INCORRECT_XML_TEXT = "<hello><world></warld></hello>";

	@Test
	public void testNoHeader() {
		InputStream is = new ByteArrayInputStream(XML_TEXT.getBytes());
		assertNotNull(DSSXMLUtils.buildDOM(is));
		assertNotNull(DSSXMLUtils.buildDOM(XML_TEXT));
		assertNotNull(DSSXMLUtils.buildDOM(new InMemoryDocument(XML_TEXT.getBytes(), "my xml")));
	}

	@Test(expected = DSSException.class)
	public void testNoHeaderError() {
		DSSXMLUtils.buildDOM(INCORRECT_XML_TEXT);
	}

	@Test
	public void testHeader() {
		InputStream is = new ByteArrayInputStream((XML_HEADER + XML_TEXT).getBytes());
		assertNotNull(DSSXMLUtils.buildDOM(is));
		assertNotNull(DSSXMLUtils.buildDOM(XML_HEADER + XML_TEXT));
		assertNotNull(DSSXMLUtils.buildDOM(new InMemoryDocument((XML_HEADER + XML_TEXT).getBytes(), "my xml")));
	}

	@Test(expected = DSSException.class)
	public void testHeaderError() {
		DSSXMLUtils.buildDOM(XML_HEADER + INCORRECT_XML_TEXT);
	}

}
