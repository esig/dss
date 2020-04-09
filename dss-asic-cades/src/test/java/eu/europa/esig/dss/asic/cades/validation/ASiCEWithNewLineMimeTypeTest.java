package eu.europa.esig.dss.asic.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class ASiCEWithNewLineMimeTypeTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(
				new FileDocument("src/test/resources/validation/asice-cades-new-line-mimetype"));
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		assertNotNull(containerInfo);
		assertEquals("ASiC-E", containerInfo.getContainerType());
		assertEquals("mimetype=application/vnd.etsi.asic-e+zip\n", containerInfo.getZipComment());
		assertTrue(containerInfo.isMimeTypeFilePresent());
		assertEquals("application/vnd.etsi.asic-e+zip\r\n", containerInfo.getMimeTypeContent());
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
