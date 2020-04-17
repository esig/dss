package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Collectors;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class XAdESAttrAuthoritiesTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-X-HR_FIN-1.xml");
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);
		
		for (SignatureWrapper signature : diagnosticData.getAllSignatures()) {
			List<RelatedCertificateWrapper> attrAuthoritiesCertValues = signature.foundCertificates().
					getRelatedCertificatesByOrigin(CertificateOrigin.ATTR_AUTORITIES_CERT_VALUES);
			assertNotNull(attrAuthoritiesCertValues);
			assertEquals(1, attrAuthoritiesCertValues.size());
			
			RelatedCertificateWrapper certificateWrapper = attrAuthoritiesCertValues.get(0);
			List<TimestampWrapper> archiveTsts = signature.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
			assertEquals(2, archiveTsts.size());
			for (TimestampWrapper archiveTimestamp : archiveTsts) {
				List<SignatureWrapper> timestampedSignatures = archiveTimestamp.getTimestampedSignatures();
				assertTrue(timestampedSignatures.contains(signature));
				
				List<CertificateWrapper> timestampedCertificates = archiveTimestamp.getTimestampedCertificates();
				List<String> timestampedCertIds = timestampedCertificates.stream().map(CertificateWrapper::getId).collect(Collectors.toList());
				assertTrue(timestampedCertIds.contains(certificateWrapper.getId()));
			}
		}
	}

}
