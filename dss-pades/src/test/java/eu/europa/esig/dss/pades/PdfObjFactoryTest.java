package eu.europa.esig.dss.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PDFTimestampService;
import eu.europa.esig.dss.pdf.PdfObjFactory;

public class PdfObjFactoryTest {

	private static final String DEFAULT_SIGNATURE_SERVICE = "PdfBoxSignatureService";
	private static final String DEFAULT_TIMESTAMP_SERVICE = "PdfBoxDocTimeStampService";

	@Test
	public void testFallback() {
		PDFSignatureService signatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
		assertNotNull(signatureService);
		assertEquals(DEFAULT_SIGNATURE_SERVICE, signatureService.getClass().getSimpleName());
		PDFTimestampService timestampService = PdfObjFactory.getInstance().newTimestampSignatureService();
		assertNotNull(timestampService);
		assertEquals(DEFAULT_TIMESTAMP_SERVICE, timestampService.getClass().getSimpleName());
	}

	@Test
	public void testSystemProperty() {
		System.setProperty("dss.pdf_obj_factory", "eu.europa.esig.dss.pdf.pdfbox.PdfBoxObjectFactory");
		PDFSignatureService signatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
		assertNotNull(signatureService);
		assertEquals(DEFAULT_SIGNATURE_SERVICE, signatureService.getClass().getSimpleName());
		PDFTimestampService timestampService = PdfObjFactory.getInstance().newTimestampSignatureService();
		assertNotNull(timestampService);
		assertEquals(DEFAULT_TIMESTAMP_SERVICE, timestampService.getClass().getSimpleName());
		System.setProperty("dss.pdf_obj_factory", "");
	}

	@Test
	public void testRuntimeChange() {
		PdfObjFactory.setInstance(new EmptyPdfObjectFactory());
		PDFSignatureService signatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
		assertNull(signatureService);
		PDFTimestampService timestampService = PdfObjFactory.getInstance().newTimestampSignatureService();
		assertNull(timestampService);

		// reset
		PdfObjFactory.setInstance(null);

		signatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
		assertNotNull(signatureService);
		assertEquals(DEFAULT_SIGNATURE_SERVICE, signatureService.getClass().getSimpleName());
	}

	private class EmptyPdfObjectFactory extends PdfObjFactory {

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
