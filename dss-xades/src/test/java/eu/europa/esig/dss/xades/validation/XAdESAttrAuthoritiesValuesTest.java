package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

/*
 * see DSS-2010
 */
public class XAdESAttrAuthoritiesValuesTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/xades-attr-authorities-values.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		List<AdvancedSignature> advancedSignatures = validator.getSignatures();
		assertEquals(1, advancedSignatures.size());
		AdvancedSignature advancedSignature = advancedSignatures.get(0);
		
		List<CertificateToken> attrAuthoritiesCertValueTokens = advancedSignature.getCertificateSource().getAttrAuthoritiesCertValues();
		assertEquals(2, attrAuthoritiesCertValueTokens.size());
		List<String> attrAuthoritiesCertIds = attrAuthoritiesCertValueTokens.stream()
				.map(CertificateToken::getDSSIdAsString).collect(Collectors.toList());
		
		List<RevocationToken<CRL>> crlAttributeValues = advancedSignature.getCRLSource().getAttributeRevocationValuesTokens();
		assertEquals(2, crlAttributeValues.size());
		// one CRL for two certs
		assertEquals(crlAttributeValues.get(0).getDSSIdAsString(), crlAttributeValues.get(1).getDSSIdAsString());
		
		List<RevocationToken<OCSP>> ocspAttributeValues = advancedSignature.getOCSPSource().getAttributeRevocationValuesTokens();
		assertEquals(1, ocspAttributeValues.size());
		
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(1, signatures.size());
		SignatureWrapper signatureWrapper = signatures.get(0);
		
		List<RelatedCertificateWrapper> attrAuthoritiesCertValues = signatureWrapper.foundCertificates().
				getRelatedCertificatesByOrigin(CertificateOrigin.ATTR_AUTORITIES_CERT_VALUES);
		assertEquals(2, attrAuthoritiesCertValues.size());
		
		List<TimestampWrapper> archiveTimestamps = signatureWrapper.getArchiveTimestamps();
		assertEquals(1, archiveTimestamps.size());
		TimestampWrapper timestampWrapper = archiveTimestamps.get(0);
		List<String> timestampedCertIds = timestampWrapper.getTimestampedCertificates().stream()
				.map(CertificateWrapper::getId).collect(Collectors.toList());
		
		for (CertificateWrapper certificateWrapper : attrAuthoritiesCertValues) {
			assertTrue(attrAuthoritiesCertIds.contains(certificateWrapper.getId()));
			assertTrue(timestampedCertIds.contains(certificateWrapper.getId()));
		}
		
		List<RelatedRevocationWrapper> attributeRevocations = signatureWrapper.foundRevocations()
				.getRelatedRevocationsByOrigin(RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
		assertEquals(2, attributeRevocations.size());
		
		int crlValues = 0;
		int ocspValues = 0;
		for (RevocationWrapper attributeRevocation : attributeRevocations) {
			List<String> timestampedRevocIds = timestampWrapper.getTimestampedRevocations().stream()
					.map(RevocationWrapper::getId).collect(Collectors.toList());
			assertTrue(timestampedRevocIds.contains(attributeRevocation.getId()));
			
			if (RevocationType.CRL.equals(attributeRevocation.getRevocationType())) {
				assertEquals(crlAttributeValues.get(0).getDSSIdAsString(), attributeRevocation.getId());
				++crlValues;
			} else if (RevocationType.OCSP.equals(attributeRevocation.getRevocationType())) {
				assertEquals(ocspAttributeValues.get(0).getDSSIdAsString(), attributeRevocation.getId());
				++ocspValues;
			}
		}
		assertEquals(1, crlValues);
		assertEquals(1, ocspValues);
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
