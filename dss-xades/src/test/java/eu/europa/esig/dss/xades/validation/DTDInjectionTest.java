package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

/**
 * Unit test added to fix issue : https://esig-dss.atlassian.net/browse/DSS-678
 */
public class DTDInjectionTest {

	@Test
	public void test() {
		SignedDocumentValidator validator = SignedDocumentValidator
				.fromDocument(new FileDocument(new File("src/test/resources/validation/xades-with-dtd-injection.xml")));
		validator.setCertificateVerifier(new CommonCertificateVerifier());

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		List<String> claimedRoles = signatures.get(0).getClaimedRoles();
		assertTrue(Utils.isCollectionEmpty(claimedRoles) || claimedRoles.contains("&test1;") || claimedRoles.contains(""));
	}

}
