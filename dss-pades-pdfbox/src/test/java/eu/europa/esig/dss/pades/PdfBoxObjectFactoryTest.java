package eu.europa.esig.dss.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PDFTimestampService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxObjectFactory;

public class PdfBoxObjectFactoryTest {

	private static final String PDFBOX_SIGNATURE_SERVICE = "PdfBoxSignatureService";

	@Test
	public void testSystemProperty() {
		PDFSignatureService signatureService = PdfObjFactory.newPAdESSignatureService();
		assertNotNull(signatureService);
		assertEquals(PDFBOX_SIGNATURE_SERVICE, signatureService.getClass().getSimpleName());
		PDFTimestampService timestampService = PdfObjFactory.newTimestampSignatureService();
		assertNotNull(timestampService);
		assertEquals(PDFBOX_SIGNATURE_SERVICE, timestampService.getClass().getSimpleName());
	}

	@Test
	public void testRuntimeChange() {
		PdfObjFactory.setInstance(new EmptyPdfObjectFactory());
		PDFSignatureService signatureService = PdfObjFactory.newPAdESSignatureService();
		assertNull(signatureService);
		PDFTimestampService timestampService = PdfObjFactory.newTimestampSignatureService();
		assertNull(timestampService);

		PdfObjFactory.setInstance(new PdfBoxObjectFactory());

		signatureService = PdfObjFactory.newPAdESSignatureService();
		assertNotNull(signatureService);
		assertEquals(PDFBOX_SIGNATURE_SERVICE, signatureService.getClass().getSimpleName());
	}

	private class EmptyPdfObjectFactory implements IPdfObjFactory {

		@Override
		public PDFSignatureService newPAdESSignatureService() {
			return null;
		}

		@Override
		public PDFTimestampService newTimestampSignatureService() {
			return null;
		}

	}

}
