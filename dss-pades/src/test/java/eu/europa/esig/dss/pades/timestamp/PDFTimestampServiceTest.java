package eu.europa.esig.dss.pades.timestamp;

import java.io.IOException;

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
		PDFTimestampService pdfTimestampService = PdfObjFactory.getInstance().newTimestampSignatureService();

		PAdESSignatureParameters parameters = new PAdESSignatureParameters();
		parameters.setSignatureName("TEST TIMESTAMP");
		DSSDocument document = new FileDocument("src/test/resources/sample.pdf");
		DSSDocument timestamped = pdfTimestampService.timestamp(document, parameters, getGoodTsa());
		timestamped.save("target/timestamped.pdf");
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
