package eu.europa.esig.dss.pades;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.esig.dss.FileDocument;

public class PDFAUtilsTest {

	@Test
	public void test() {
		assertTrue(PDFAUtils.validatePDFAStructure(new FileDocument("src/test/resources/not_signed_pdfa.pdf")));
	}

	@Test
	public void testNotPDFA() {
		assertFalse(PDFAUtils.validatePDFAStructure(new FileDocument("src/test/resources/sample.pdf")));
	}

}
