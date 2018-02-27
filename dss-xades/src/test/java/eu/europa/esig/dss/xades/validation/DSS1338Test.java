package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1338Test {

	@Test
	public void test() throws UnsupportedEncodingException {
		DSSDocument doc = new FileDocument("src/test/resources/validation/11068_signed.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		String firstSignatureId = reports.getSimpleReport().getFirstSignatureId();

		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(firstSignatureId);
		assertEquals(1, originalDocuments.size());

		for (DSSDocument dssDocument : originalDocuments) {
			byte[] byteArray = DSSUtils.toByteArray(dssDocument);
			String signedContent = new String(byteArray, "UTF-8");
			assertTrue(signedContent.contains("<ns2:flusso xmlns:ns2=\"http://www.bancaditalia.it"));
			assertTrue(signedContent.endsWith("</ns2:flusso>"));
			assertFalse(signedContent.contains("<ds:Object"));
		}

	}

}
