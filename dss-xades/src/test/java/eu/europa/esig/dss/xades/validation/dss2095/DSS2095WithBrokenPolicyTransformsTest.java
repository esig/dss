package eu.europa.esig.dss.xades.validation.dss2095;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

public class DSS2095WithBrokenPolicyTransformsTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss2095/sigPolicyWithBrokenTransforms.xml");
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		
		Map<String, DSSDocument> mapById = new HashMap<>();
		mapById.put("urn:sbr:signature-policy:xml:2.0", new FileDocument("src/test/resources/validation/dss2095/SBR-signature-policy-v2.0.xml"));
		
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		signaturePolicyProvider.setSignaturePoliciesById(mapById);
		
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		
		return validator;
	}
	
	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isPolicyIdentified());
		assertNotNull(signature.getPolicyId());
		assertNotNull(signature.getPolicyUrl());
		assertTrue(signature.isPolicyPresent());
		assertFalse(signature.isPolicyStatus());
		assertFalse(signature.isPolicyAsn1Processable());
		assertFalse(signature.isPolicyZeroHash());
		assertFalse(Utils.isStringEmpty(signature.getPolicyProcessingError()));
		
		List<String> policyTransforms = signature.getPolicyTransforms();
		assertTrue(Utils.isCollectionNotEmpty(policyTransforms));
		assertEquals(1, policyTransforms.size());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(3, digestMatchers.size());
		
		int references = 0;
		int signedProperties = 0;
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			if (DigestMatcherType.REFERENCE.equals(digestMatcher.getType())) {
				assertFalse(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				++references;
			} else if (DigestMatcherType.SIGNED_PROPERTIES.equals(digestMatcher.getType())) {
				assertTrue(digestMatcher.isDataFound());
				assertFalse(digestMatcher.isDataIntact());
				++signedProperties;
			}
		}
		assertEquals(2, references);
		assertEquals(1, signedProperties);
	};
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		assertFalse(signature.isSigningCertificateIdentified());
		assertTrue(signature.isSigningCertificateReferencePresent());
		assertTrue(signature.isSigningCertificateReferenceUnique());
		
		CertificateRefWrapper signingCertificateReference = signature.getSigningCertificateReference();
		assertNotNull(signingCertificateReference);
		assertTrue(signingCertificateReference.isDigestValuePresent());
		assertTrue(signingCertificateReference.isDigestValueMatch());
		
		assertNull(signingCertificateReference.getIssuerName());
		assertNull(signingCertificateReference.getIssuerSerial());
		assertTrue(signingCertificateReference.isIssuerSerialPresent());
		assertFalse(signingCertificateReference.isIssuerSerialMatch()); // non-conformant X509IssuerName
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getOriginalSignerDocuments().size());
	}
	
	@Override
	protected void validateETSISignerDocuments(List<SignersDocumentType> signersDocuments) {
		assertEquals(0, signersDocuments.size());
	}

}
