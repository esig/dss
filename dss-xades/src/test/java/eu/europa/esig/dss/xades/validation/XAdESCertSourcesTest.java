package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class XAdESCertSourcesTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-X-HU_POL-3.xml");
	}
	
	@Override
	protected void checkCertificateChain(DiagnosticData diagnosticData) {
		super.checkCertificateChain(diagnosticData);
		
		List<CertificateWrapper> certificates = diagnosticData.getUsedCertificates();
		for (CertificateWrapper certificate : certificates) {
			assertNotNull(certificate.getSources());
			assertNotEquals(0, certificate.getSources().size());
			assertFalse(certificate.getSources().contains(CertificateSourceType.UNKNOWN));
		}
	}

}
