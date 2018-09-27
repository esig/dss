package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class DSS1444 {

	@Test
	public void validateImageAndGetEmptyReport() {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"));

		PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
	}

}
