package eu.europa.esig.dss.jades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerRole;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;

public class JAdESWithCertifiedCertTest extends AbstractJAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/jades-with-certified.json");
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		List<XmlSignerRole> certifiedRoles = signature.getCertifiedRoles();
		assertNotNull(certifiedRoles);
		assertEquals(1, certifiedRoles.size());

		XmlSignerRole xmlSignerRole = certifiedRoles.get(0);
		assertEquals(EndorsementType.CERTIFIED, xmlSignerRole.getCategory());
		assertNotNull(xmlSignerRole.getRole());

		CertificateToken certificateToken = DSSUtils.loadCertificateFromBase64EncodedString(xmlSignerRole.getRole());
		assertNotNull(certificateToken);
	}

}
