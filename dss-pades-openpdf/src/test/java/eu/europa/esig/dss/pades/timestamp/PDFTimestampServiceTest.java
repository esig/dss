package eu.europa.esig.dss.pades.timestamp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.junit.Test;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pdf.PDFTimestampService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.signature.PKIFactoryAccess;

public class PDFTimestampServiceTest extends PKIFactoryAccess {

	@Test
	@SuppressWarnings("unchecked")
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
		
		try (InputStream is = timestamped.openStream(); PdfReader reader = new PdfReader(is)) {
			AcroFields af = reader.getAcroFields();

			List<String> names = af.getSignatureNames();
			assertEquals(1, names.size());
			
			String first = names.get(0);
			
			PdfDictionary signatureDictionary = af.getSignatureDictionary(first);
			assertNull(signatureDictionary.get(PdfName.REASON));
			assertNull(signatureDictionary.get(PdfName.NAME));
			assertNull(signatureDictionary.get(PdfName.LOCATION));
			assertNull(signatureDictionary.get(PdfName.CONTACTINFO));
			assertNull(signatureDictionary.get(PdfName.M));
		}
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
