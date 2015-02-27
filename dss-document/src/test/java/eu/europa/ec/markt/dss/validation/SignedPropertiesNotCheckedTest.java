package eu.europa.ec.markt.dss.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DetailedReport;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.rules.SubIndication;

/**
 * Unit test added to fix : https://joinup.ec.europa.eu/asset/sd-dss/issue/xades-signedproperties-reference
 *
 * XAdES standard : The generator shall create as many <code>ds:Reference</code> element as signed data objects (each one referencing one of them)
 * plus one ds:Reference element referencing xades:SignedProperties element.
 */
public class SignedPropertiesNotCheckedTest {

	private static final String REFERENCE_DATA_FOUND_PATH = "/DiagnosticData/Signature[@Id='%s']/BasicSignature/ReferenceDataFound/text()";

	@Test
	public void testNoSignedProperties() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/join-up/xades_no-signedpropref.asice_.zip");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertFalse(diagnosticData.getBoolValue(REFERENCE_DATA_FOUND_PATH, diagnosticData.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, detailedReport.getBasicBuildingBlocksSubIndication(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testWithSignedProperties() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-signed.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		validator.validateDocument();

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertTrue(diagnosticData.getBoolValue(REFERENCE_DATA_FOUND_PATH, diagnosticData.getFirstSignatureId()));
	}

}
