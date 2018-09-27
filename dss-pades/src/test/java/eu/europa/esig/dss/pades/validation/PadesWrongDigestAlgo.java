package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class PadesWrongDigestAlgo {

	@Test
	public void test() throws Exception {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new InMemoryDocument(getClass().getResourceAsStream("/validation/wrong-digest-algo.pdf")));
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getAllSignatures().size());
		assertEquals(4, diagnosticData.getAllTimestamps().size());
	}

}
