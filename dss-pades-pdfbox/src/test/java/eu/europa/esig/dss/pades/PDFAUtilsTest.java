package eu.europa.esig.dss.pades;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.InMemoryDocument;

public class PDFAUtilsTest {

	@Test
	public void test() {
		assertTrue(PDFAUtils.validatePDFAStructure(new InMemoryDocument(getClass().getResourceAsStream("/not_signed_pdfa.pdf"))));
	}

	@Test
	public void testNotPDFA() {
		assertFalse(PDFAUtils.validatePDFAStructure(new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"))));
	}

}
