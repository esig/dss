package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class SignatureTimestampCertificateNotFound {

	@Test
	public void test() throws Exception {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new InMemoryDocument(getClass().getResourceAsStream("/validation/TestToSignPDFSHA256_TST_SIG_NOT_FOUND.pdf")));
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setIncludeTimestampTokenValues(true);
		validator.setCertificateVerifier(certificateVerifier);

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signatureWrapper);
		List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
		assertEquals(1, timestampList.size());
		TimestampWrapper timestampWrapper = timestampList.get(0);
		assertNull(timestampWrapper.getSigningCertificate());
	}

}
