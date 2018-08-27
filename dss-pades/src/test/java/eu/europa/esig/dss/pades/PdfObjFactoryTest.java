package eu.europa.esig.dss.pades;

import org.junit.Test;

import eu.europa.esig.dss.pdf.PdfObjFactory;

public class PdfObjFactoryTest {

	@Test(expected = ExceptionInInitializerError.class)
	public void testFallback() {
		PdfObjFactory.newPAdESSignatureService();
	}

}
