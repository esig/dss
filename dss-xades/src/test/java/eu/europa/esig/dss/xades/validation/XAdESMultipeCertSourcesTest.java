package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class XAdESMultipeCertSourcesTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-X-CZ_SEF-5.xml");
	}
	
	@Override
	protected void checkCertificateChain(DiagnosticData diagnosticData) {
		super.checkCertificateChain(diagnosticData);
		
		List<CertificateWrapper> certificates = diagnosticData.getUsedCertificates();
		int certsFromTimestamp = 0;
		for (CertificateWrapper certificate : certificates) {
			List<CertificateSourceType> certSources = certificate.getSources();
			assertNotNull(certSources);
			assertNotEquals(0, certSources.size());
			if (certSources.contains(CertificateSourceType.TIMESTAMP)) {
				assertEquals(2, certSources.size());
				assertTrue(certSources.contains(CertificateSourceType.SIGNATURE));
				certsFromTimestamp++;
			}
			assertFalse(certificate.getSources().contains(CertificateSourceType.UNKNOWN));
			assertNotNull(certificate.getDigestAlgoAndValue());
			assertEquals(DigestAlgorithm.SHA256, certificate.getDigestAlgoAndValue().getDigestMethod());
		}
		assertEquals(1, certsFromTimestamp);
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		AdvancedSignature advancedSignature = advancedSignatures.get(0);
		SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
		
		SignatureWrapper signature = diagnosticData.getSignatureById(advancedSignature.getId());
		FoundCertificatesProxy foundCertificates = signature.foundCertificates();
		
		assertEquals(certificateSource.getSigningCertificateRefs().size(),
				foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size() +
				foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
		
		List<TimestampToken> allTimestamps = advancedSignature.getAllTimestamps();
		assertEquals(1, allTimestamps.size());
		TimestampToken timestampToken = allTimestamps.get(0);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		TimestampWrapper timestampWrapper = timestampList.get(0);

		certificateSource = timestampToken.getCertificateSource();
		foundCertificates = timestampWrapper.foundCertificates();
		assertEquals(certificateSource.getSigningCertificateRefs().size(),
				foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size() +
				foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(1, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}

}
