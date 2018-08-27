package eu.europa.esig.dss.pades.timestamp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pdf.PDFTimestampService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.signature.PKIFactoryAccess;

public class PDFTimestampServiceTest extends PKIFactoryAccess {

	@Test
	public void timestampAlone() throws IOException {

		PDFTimestampService pdfTimestampService = PdfObjFactory.newTimestampSignatureService();

		PAdESSignatureParameters parameters = new PAdESSignatureParameters();

		// The following parameters MUST be ignored (ETSI EN 319 142-1 V1.1.1, section 5.4.3)
		parameters.setLocation("LOCATION");
		parameters.setSignatureName("TEST TIMESTAMP");
		parameters.setReason("REASON");
		parameters.setContactInfo("CONTACT INFO");

		DSSDocument document = new FileDocument("src/test/resources/sample.pdf");
		DSSDocument timestamped = pdfTimestampService.timestamp(document, parameters, getGoodTsa());
		timestamped.save("target/timestamped.pdf");

		try (InputStream is = timestamped.openStream(); PDDocument doc = PDDocument.load(is)) {
			List<PDSignature> signatureDictionaries = doc.getSignatureDictionaries();
			assertEquals(1, signatureDictionaries.size());
			PDSignature pdSignature = signatureDictionaries.get(0);
			assertNull(pdSignature.getName());
			assertNull(pdSignature.getReason());
			assertNull(pdSignature.getLocation());
			assertNull(pdSignature.getContactInfo());
			assertNull(pdSignature.getSignDate()); // M
			assertEquals("Adobe.PPKLite", pdSignature.getFilter());
			assertEquals("ETSI.RFC3161", pdSignature.getSubFilter());
		}
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
