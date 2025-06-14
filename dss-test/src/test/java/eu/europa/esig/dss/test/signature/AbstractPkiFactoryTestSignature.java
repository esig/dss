/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.test.signature;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.OrphanCertificateWrapper;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.AbstractSerializableSignatureParameters;
import eu.europa.esig.dss.model.CommonCommitmentType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.UserNotice;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SACommitmentTypeIndicationType;
import eu.europa.esig.validationreport.jaxb.SAOneSignerRoleType;
import eu.europa.esig.validationreport.jaxb.SASignatureProductionPlaceType;
import eu.europa.esig.validationreport.jaxb.SASignerRoleType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import jakarta.xml.bind.JAXBElement;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractPkiFactoryTestSignature<SP extends SerializableSignatureParameters, 
				TP extends SerializableTimestampParameters> extends AbstractPkiFactoryTestValidation {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractPkiFactoryTestSignature.class);

	protected abstract SP getSignatureParameters();

	protected abstract MimeType getExpectedMime();

	protected abstract boolean isBaselineT();

	protected abstract boolean isBaselineLTA();
	
	@Test
	public void signAndVerify() {
		final DSSDocument signedDocument = sign();

		assertNotNull(signedDocument.getName());
		assertNotNull(signedDocument.getMimeType());

		// signedDocument.save("target/" + signedDocument.getName());

        byte[] byteArray = DSSUtils.toByteArray(signedDocument);
		onDocumentSigned(byteArray);
		if (LOG.isDebugEnabled()) {
			LOG.debug(new String(byteArray));
		}

		checkMimeType(signedDocument);
		
		verify(signedDocument);
	}

	protected void onDocumentSigned(byte[] byteArray) {
		assertTrue(Utils.isArrayNotEmpty(byteArray));
	}

	protected void checkMimeType(DSSDocument signedDocument) {
		assertEquals(getExpectedMime(), signedDocument.getMimeType());
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		for (AdvancedSignature signature : signatures) {
			assertNotNull(signature.getFilename());
		}
	}

	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);
		assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));
	}

	@Override
	protected void checkDigestAlgorithm(DiagnosticData diagnosticData) {
		super.checkDigestAlgorithm(diagnosticData);
		assertEquals(getSignatureParameters().getDigestAlgorithm(), diagnosticData.getSignatureDigestAlgorithm(diagnosticData.getFirstSignatureId()));
	}

	@SuppressWarnings({ "unchecked" })
	@Override
	protected void checkEncryptionAlgorithm(DiagnosticData diagnosticData) {
		super.checkEncryptionAlgorithm(diagnosticData);
		
		AbstractSerializableSignatureParameters<TP> signatureParameters = (AbstractSerializableSignatureParameters<TP>) getSignatureParameters();
		assertEquals(signatureParameters.getSignatureAlgorithm().getEncryptionAlgorithm(),
				diagnosticData.getSignatureEncryptionAlgorithm(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		super.checkSigningCertificateValue(diagnosticData);
		
		String signingCertificateId = diagnosticData.getSigningCertificateId(diagnosticData.getFirstSignatureId());
		CertificateToken certificate = getSigningCert();
		String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
		String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
		assertEquals(certificate.getSubject().getRFC2253(), certificateDN);
		assertEquals(certificate.getSerialNumber().toString(), certificateSerialNumber);

		SignatureAlgorithm signatureAlgorithm = certificate.getSignatureAlgorithm();
		CertificateWrapper certificateWrapper = diagnosticData.getUsedCertificateById(signingCertificateId);
		assertEquals(signatureAlgorithm.getDigestAlgorithm(), certificateWrapper.getDigestAlgorithm());
		assertEquals(signatureAlgorithm.getEncryptionAlgorithm(), certificateWrapper.getEncryptionAlgorithm());
	}

	@Override
	protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
		super.checkIssuerSigningCertificateValue(diagnosticData);
		
		String signingCertificateId = diagnosticData.getSigningCertificateId(diagnosticData.getFirstSignatureId());
		String issuerDN = diagnosticData.getCertificateIssuerDN(signingCertificateId);
		CertificateToken certificate = getSigningCert();
		assertEquals(certificate.getIssuer().getRFC2253(), issuerDN);
	}

	@Override
	@SuppressWarnings({ "unchecked" })
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);
		
		AbstractSerializableSignatureParameters<TP> signatureParameters = (AbstractSerializableSignatureParameters<TP>) getSignatureParameters();
		assertEquals(signatureParameters.getSignatureLevel(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected void checkCertificateChain(DiagnosticData diagnosticData) {
		super.checkCertificateChain(diagnosticData);

		List<String> signatureCertificateChain = diagnosticData.getSignatureCertificateChainIds(diagnosticData.getFirstSignatureId());
		assertTrue(Utils.isCollectionNotEmpty(signatureCertificateChain));
		// upper certificate than trust anchors are ignored
		assertTrue(getCertificateChain().length >= signatureCertificateChain.size());
	}

	@Override
	protected void checkCertificates(DiagnosticData diagnosticData) {
		super.checkCertificates(diagnosticData);
		checkCertificateValuesEncapsulation(diagnosticData);
	}

	protected void checkCertificateValuesEncapsulation(DiagnosticData diagnosticData) {
		// Signature certificate chain validation
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			List<RelatedCertificateWrapper> certificateValues = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES);
			if (Utils.isCollectionNotEmpty(certificateValues)) {
				List<String> signatureCertificateIds = populateWithRevocationCertificatesRecursively(new ArrayList<>(), signature.getCertificateChain());
				for (SignatureWrapper counterSignature : diagnosticData.getAllCounterSignaturesForMasterSignature(signature)) {
					populateWithRevocationCertificatesRecursively(signatureCertificateIds, counterSignature.getCertificateChain());
					for (TimestampWrapper timestamp : counterSignature.getTimestampList()) {
						populateWithRevocationCertificatesRecursively(signatureCertificateIds, timestamp.getCertificateChain());
					}
				}
				for (CertificateWrapper certificate : certificateValues) {
					assertTrue(signatureCertificateIds.contains(certificate.getId()));
				}
			}
			// Timestamp certificate chain validation
			List<RelatedCertificateWrapper> tstValidationData = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA);
			if (Utils.isCollectionNotEmpty(tstValidationData)) {
				List<String> timestampCertificateIds = new ArrayList<>();
				for (TimestampWrapper timestamp : signature.getTimestampList()) {
					populateWithRevocationCertificatesRecursively(timestampCertificateIds, timestamp.getCertificateChain());
				}
				for (CertificateWrapper certificate : tstValidationData) {
					assertTrue(timestampCertificateIds.contains(certificate.getId()));
				}
			}
			// Any validation data validation
			List<RelatedCertificateWrapper> anyValidationData = signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA);
			if (Utils.isCollectionNotEmpty(anyValidationData)) {
				List<String> certificateIds = populateWithRevocationCertificatesRecursively(new ArrayList<>(), signature.getCertificateChain());
				for (TimestampWrapper timestamp : signature.getTimestampList()) {
					populateWithRevocationCertificatesRecursively(certificateIds, timestamp.getCertificateChain());
				}
				for (SignatureWrapper counterSignature : diagnosticData.getAllCounterSignaturesForMasterSignature(signature)) {
					populateWithRevocationCertificatesRecursively(certificateIds, counterSignature.getCertificateChain());
					for (TimestampWrapper timestamp : counterSignature.getTimestampList()) {
						populateWithRevocationCertificatesRecursively(certificateIds, timestamp.getCertificateChain());
					}
				}
				for (CertificateWrapper certificate : anyValidationData) {
					assertTrue(certificateIds.contains(certificate.getId()));
				}
			}
		}
	}

	protected List<String> populateWithRevocationCertificatesRecursively(List<String> certIdList, List<CertificateWrapper> certChain) {
		for (CertificateWrapper certificateWrapper : certChain) {
			if (!certIdList.contains(certificateWrapper.getId())) {
				certIdList.add(certificateWrapper.getId());
				for (RevocationWrapper revocationWrapper : certificateWrapper.getCertificateRevocationData()) {
					populateWithRevocationCertificatesRecursively(certIdList, revocationWrapper.getCertificateChain());
				}
			}
		}
		return certIdList;
	}

	@Override
	protected void checkSigningDate(DiagnosticData diagnosticData) {
		super.checkSigningDate(diagnosticData);
		
		Date signatureDate = diagnosticData.getFirstSignatureDate();
		Date originalSigningDate = getSignatureParameters().bLevel().getSigningDate();

		// Date in signed documents is truncated
		assertEquals(DSSUtils.formatDateToRFC(originalSigningDate), DSSUtils.formatDateToRFC(signatureDate));
	}
	
	@Override
	@SuppressWarnings("unchecked")
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<String> timestampIdList = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		int nbContentTimestamps = 0;
		if (Utils.isCollectionNotEmpty(timestampIdList)) {
			for (String timestampId : timestampIdList) {
				TimestampType timestampType = diagnosticData.getTimestampType(timestampId);
				switch (timestampType) {
					case CONTENT_TIMESTAMP:
					case ALL_DATA_OBJECTS_TIMESTAMP:
					case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
						nbContentTimestamps++;
						break;
					default:
						break;
					}
			}
		}
		AbstractSignatureParameters<TP> signatureParameters = (AbstractSignatureParameters<TP>) getSignatureParameters();
		assertEquals(nbContentTimestamps, Utils.collectionSize(signatureParameters.getContentTimestamps()));
	}

	@Override
	protected void checkCommitmentTypeIndications(DiagnosticData diagnosticData) {
		super.checkCommitmentTypeIndications(diagnosticData);
		
		List<CommitmentType> commitmentTypeIndications = getSignatureParameters().bLevel().getCommitmentTypeIndications();
		if (Utils.isCollectionNotEmpty(commitmentTypeIndications)) {
			SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
			List<XmlCommitmentTypeIndication> foundCommitmentTypeIdentifiers = signatureWrapper.getCommitmentTypeIndications();
			assertTrue(Utils.isCollectionNotEmpty(foundCommitmentTypeIdentifiers));
			for (CommitmentType commitmentTypeIndication : commitmentTypeIndications) {
				boolean commitmentFound = false;
				for (XmlCommitmentTypeIndication xmlCommitmentTypeIndication : foundCommitmentTypeIdentifiers) {
					String indication = xmlCommitmentTypeIndication.getIdentifier();
					assertNotNull(indication);
					
					boolean uriMatch;
					SignatureForm signatureForm = signatureWrapper.getSignatureFormat().getSignatureForm();
					switch (signatureForm) {
						case XAdES:
						case JAdES:
							uriMatch = indication.equals(commitmentTypeIndication.getUri()) || indication.equals(DSSUtils.getOidCode(commitmentTypeIndication.getOid()));
							break;
						case CAdES:
						case PAdES:
							uriMatch = indication.equals(commitmentTypeIndication.getOid());
							break;
						default:
							throw new DSSException(String.format("The signature format [%s] is not supported!", signatureForm));
					}
					
					if (uriMatch) {
						commitmentFound = true;
						if (SignatureForm.XAdES.equals(signatureForm) && commitmentTypeIndication.getDescription() != null) {
							assertEquals(commitmentTypeIndication.getDescription(), xmlCommitmentTypeIndication.getDescription());
						}
						if (SignatureForm.XAdES.equals(signatureForm) && Utils.isArrayNotEmpty(commitmentTypeIndication.getDocumentationReferences())) {
							assertEquals(Arrays.asList(commitmentTypeIndication.getDocumentationReferences()), xmlCommitmentTypeIndication.getDocumentationReferences());
						}
						if (SignatureForm.XAdES.equals(signatureForm) && commitmentTypeIndication instanceof CommonCommitmentType) {
							CommonCommitmentType commonCommitmentType = (CommonCommitmentType) commitmentTypeIndication;
							if (Utils.isArrayNotEmpty(commonCommitmentType.getSignedDataObjects())) {
								assertEquals(Arrays.asList(commonCommitmentType.getSignedDataObjects()), xmlCommitmentTypeIndication.getObjectReferences());
							} else {
								assertTrue(xmlCommitmentTypeIndication.isAllDataSignedObjects() != null
										&& xmlCommitmentTypeIndication.isAllDataSignedObjects());
							}
						}
					}
				}
				
				assertTrue(commitmentFound);
			}
		}
	}

	@Override
	protected void checkClaimedRoles(DiagnosticData diagnosticData) {
		super.checkClaimedRoles(diagnosticData);
		
		List<String> claimedRoles = getSignatureParameters().bLevel().getClaimedSignerRoles();

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<String> foundClaimedRoles = signatureWrapper.getSignerRoleDetails(signatureWrapper.getClaimedRoles());

		assertEquals(Utils.collectionSize(claimedRoles), Utils.collectionSize(foundClaimedRoles));
		if (Utils.isCollectionNotEmpty(claimedRoles)) {
			assertEquals(claimedRoles, foundClaimedRoles);
		}
	}
	
	@Override
	protected void checkSignedAssertions(DiagnosticData diagnosticData) {
		super.checkSignedAssertions(diagnosticData);

		List<String> signedAssertions = getSignatureParameters().bLevel().getSignedAssertions();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<String> foundSignedAssertionRoles = signatureWrapper.getSignerRoleDetails(signatureWrapper.getSignedAssertions());

		assertEquals(Utils.collectionSize(signedAssertions), Utils.collectionSize(foundSignedAssertionRoles));
		if (Utils.isCollectionNotEmpty(signedAssertions)) {
			for (int i = 0; i < signedAssertions.size(); i++) {
				assertTrue(areSignedAssertionsEqual(signedAssertions.get(i), foundSignedAssertionRoles.get(i)));
			}
		}
	}

	protected boolean areSignedAssertionsEqual(String signedAssertionOne, String signedAssertionTwo) {
		return signedAssertionOne.equals(signedAssertionTwo);
	}

	@Override
	protected void checkSignatureProductionPlace(DiagnosticData diagnosticData) {
		super.checkSignatureProductionPlace(diagnosticData);

		SignerLocation signerLocation = getSignatureParameters().bLevel().getSignerLocation();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(signerLocation != null && !signerLocation.isEmpty(),
				signatureWrapper.isSignatureProductionPlacePresent());

		if (signerLocation != null) {
			String country = signerLocation.getCountry();
			if (Utils.isStringNotEmpty(country)) {
				assertEquals(country, signatureWrapper.getCountryName());
			}
			String locality = signerLocation.getLocality();
			if (Utils.isStringNotEmpty(locality)) {
				assertEquals(locality, signatureWrapper.getCity());
			}
			List<String> postalAddress = signerLocation.getPostalAddress();
			if (Utils.isCollectionNotEmpty(postalAddress)) {
				assertEquals(postalAddress, signatureWrapper.getPostalAddress());
			}
			String postalCode = signerLocation.getPostalCode();
			if (Utils.isStringNotEmpty(postalCode)) {
				assertEquals(postalCode, signatureWrapper.getPostalCode());
			}
			String postOfficeBoxNumber = signerLocation.getPostOfficeBoxNumber();
			if (Utils.isStringNotEmpty(postOfficeBoxNumber)) {
				assertEquals(postOfficeBoxNumber, signatureWrapper.getPostOfficeBoxNumber());
			}
			String stateOrProvince = signerLocation.getStateOrProvince();
			if (Utils.isStringNotEmpty(stateOrProvince)) {
				assertEquals(stateOrProvince, signatureWrapper.getStateOrProvince());
			}
			String street = signerLocation.getStreetAddress();
			if (Utils.isStringNotEmpty(street)) {
				assertEquals(street, signatureWrapper.getStreetAddress());
			}
		}
	}

	@Override
	@SuppressWarnings({ "unchecked" })
	protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
		super.checkMessageDigestAlgorithm(diagnosticData);

		AbstractSerializableSignatureParameters<TP> signatureParameters = (AbstractSerializableSignatureParameters<TP>) getSignatureParameters();
		DigestAlgorithm expectedDigestAlgorithm = signatureParameters.getReferenceDigestAlgorithm();
		if (expectedDigestAlgorithm == null) {
			expectedDigestAlgorithm = getSignatureParameters().getDigestAlgorithm();
		}

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			if (!DigestMatcherType.MANIFEST_ENTRY.equals(xmlDigestMatcher.getType())) {
				assertEquals(expectedDigestAlgorithm, xmlDigestMatcher.getDigestMethod());
			}
		}
	}

	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);
		
		Policy signaturePolicy = getSignatureParameters().bLevel().getSignaturePolicy();
		if (signaturePolicy != null) {
			SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
			assertTrue(signature.isPolicyPresent());

			if (Utils.isStringNotEmpty(signaturePolicy.getId())) {
				assertTrue(signaturePolicy.getId().contains(diagnosticData.getFirstPolicyId())); // initial Id can contain "urn:oid:"
				// or IMPLICIT_POLICY by default if it is not specified
			}

			if (Utils.isStringNotEmpty(signaturePolicy.getDescription())) {
				assertEquals(signaturePolicy.getDescription(), diagnosticData.getPolicyDescription(signature.getId()));
			} else {
				assertTrue(Utils.isStringEmpty(signature.getPolicyDescription()));
			}

			if (Utils.isArrayNotEmpty(signaturePolicy.getDocumentationReferences())) {
				assertEquals(Arrays.asList(signaturePolicy.getDocumentationReferences()), diagnosticData.
						getPolicyDocumentationReferences(signature.getId()));
			} else {
				assertTrue(Utils.isCollectionEmpty(signature.getPolicyDocumentationReferences()));
			}

			if (Utils.isStringNotEmpty(signaturePolicy.getSpuri())) {
				assertEquals(signaturePolicy.getSpuri(), signature.getPolicyUrl());
			} else if (Utils.isStringNotEmpty(signaturePolicy.getId())) {
				assertEquals(signaturePolicy.getId(), signature.getPolicyUrl());
			} else {
				assertTrue(Utils.isStringEmpty(signature.getPolicyUrl()));
			}

			UserNotice userNotice = signaturePolicy.getUserNotice();
			if (userNotice != null) {
				assertNotNull(signature.getPolicyUserNotice());
				if (Utils.isStringNotEmpty(userNotice.getOrganization())) {
					assertEquals(userNotice.getOrganization(), signature.getPolicyUserNotice().getOrganization());
				}
				if (userNotice.getNoticeNumbers() != null && userNotice.getNoticeNumbers().length > 0) {
					assertEquals(DSSUtils.toBigIntegerList(userNotice.getNoticeNumbers()), signature.getPolicyUserNotice().getNoticeNumbers());
				}
				if (Utils.isStringNotEmpty(userNotice.getExplicitText())) {
					assertEquals(userNotice.getExplicitText(), signature.getPolicyUserNotice().getExplicitText());
				}
			}

			SpDocSpecification spDocSpecification = signaturePolicy.getSpDocSpecification();
			if (spDocSpecification != null) {
				assertNotNull(signature.getPolicyDocSpecification());
				if (Utils.isStringNotEmpty(spDocSpecification.getId())) {
					assertEquals(DSSUtils.getObjectIdentifierValue(spDocSpecification.getId()), signature.getPolicyDocSpecification().getId());
				}
			}
		}
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		for (RevocationWrapper revocationWrapper : diagnosticData.getAllRevocationData()) {
			assertNotNull(revocationWrapper.getId());
			assertNotNull(revocationWrapper.getRevocationType());
			assertNotNull(revocationWrapper.getOrigin());
			assertNotNull(revocationWrapper.getProductionDate());
			assertNotNull(revocationWrapper.getSigningCertificate());
			assertTrue(Utils.isCollectionNotEmpty(revocationWrapper.getCertificateChain()));
			assertNotNull(revocationWrapper.foundCertificates());
			assertNotNull(revocationWrapper.foundCertificates().getRelatedCertificates());
			assertNotNull(revocationWrapper.foundCertificates().getOrphanCertificates());
			if (RevocationType.OCSP.equals(revocationWrapper.getRevocationType())) {
				assertTrue(Utils.isCollectionNotEmpty(revocationWrapper.foundCertificates().getRelatedCertificates()));
				assertTrue(Utils.isCollectionNotEmpty(revocationWrapper.foundCertificates().getRelatedCertificateRefs()));
				boolean signingCertFound = false;
				for (RelatedCertificateWrapper certificateWrapper : revocationWrapper.foundCertificates().getRelatedCertificates()) {
					assertTrue(certificateWrapper.getSources().contains(CertificateSourceType.OCSP_RESPONSE));
					assertTrue(Utils.isCollectionNotEmpty(certificateWrapper.getOrigins()));
					for (CertificateRefWrapper refWrapper : certificateWrapper.getReferences()) {
						if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(refWrapper.getOrigin())) {
							signingCertFound = true;
						}
						assertTrue(refWrapper.getSki() != null || refWrapper.getIssuerName() != null);
						assertNull(refWrapper.getDigestAlgoAndValue());
						assertNull(refWrapper.getIssuerSerial());
						assertEquals(certificateWrapper.getId(), revocationWrapper.getSigningCertificate().getId());
					}
				}
				assertTrue(signingCertFound);
			}
		}
		checkRevocationDataEncapsulation(diagnosticData);
	}

	protected void checkRevocationDataEncapsulation(DiagnosticData diagnosticData) {
		for (SignatureWrapper signature : diagnosticData.getSignatures()) {
			List<RelatedRevocationWrapper> sigRevocationWrappers = signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES);
			if (Utils.isCollectionNotEmpty(sigRevocationWrappers)) {
				List<String> revIdList = new ArrayList<>();
				for (CertificateWrapper certificateWrapper : signature.getCertificateChain()) {
					populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
				}
				for (SignatureWrapper counterSignature : diagnosticData.getAllCounterSignaturesForMasterSignature(signature)) {
					for (CertificateWrapper certificateWrapper : counterSignature.getCertificateChain()) {
						populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
					}
				}
				for (RevocationWrapper revocation : sigRevocationWrappers) {
					assertTrue(revIdList.contains(revocation.getId()));
				}
			}
			List<RelatedRevocationWrapper> tstRevocationWrappers = signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.TIMESTAMP_VALIDATION_DATA);
			if (Utils.isCollectionNotEmpty(tstRevocationWrappers)) {
				List<String> revIdList = new ArrayList<>();
				for (TimestampWrapper timestampWrapper : signature.getTimestampList()) {
					for (CertificateWrapper certificateWrapper : timestampWrapper.getCertificateChain()) {
						populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
					}
				}
				for (RevocationWrapper revocation : tstRevocationWrappers) {
					assertTrue(revIdList.contains(revocation.getId()));
				}
			}
			List<RelatedRevocationWrapper> anyValidationData = signature.foundRevocations().getRelatedRevocationsByOrigin(RevocationOrigin.ANY_VALIDATION_DATA);
			if (Utils.isCollectionNotEmpty(anyValidationData)) {
				List<String> revIdList = new ArrayList<>();
				for (CertificateWrapper certificateWrapper : signature.getCertificateChain()) {
					populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
				}
				for (TimestampWrapper timestampWrapper : signature.getTimestampList()) {
					for (CertificateWrapper certificateWrapper : timestampWrapper.getCertificateChain()) {
						populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
					}
				}
				for (SignatureWrapper counterSignature : diagnosticData.getAllCounterSignaturesForMasterSignature(signature)) {
					for (CertificateWrapper certificateWrapper : counterSignature.getCertificateChain()) {
						populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
					}
					for (TimestampWrapper timestamp : counterSignature.getTimestampList()) {
						for (CertificateWrapper certificateWrapper : timestamp.getCertificateChain()) {
							populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
						}
					}
				}
				for (RevocationWrapper revocation : anyValidationData) {
					assertTrue(revIdList.contains(revocation.getId()));
				}
			}
		}
	}

	private List<String> populateWithRevocationDataRecursively(List<String> revIdList, List<? extends RevocationWrapper> revocationData) {
		for (RevocationWrapper revocationWrapper : revocationData) {
			if (!revIdList.contains(revocationWrapper.getId())) {
				revIdList.add(revocationWrapper.getId());
				for (CertificateWrapper certificateWrapper : revocationWrapper.getCertificateChain()) {
					populateWithRevocationDataRecursively(revIdList, certificateWrapper.getCertificateRevocationData());
				}
			}
		}
		return revIdList;
	}

	@Override
	protected void checkNoDuplicateCompleteCertificates(FoundCertificatesProxy foundCertificates) {
		super.checkNoDuplicateCompleteCertificates(foundCertificates);
		
		List<RelatedCertificateWrapper> relatedCertificates = foundCertificates.getRelatedCertificates();
		for (RelatedCertificateWrapper foundCert : relatedCertificates) {
			assertTrue(foundCert.getOrigins().size() < 2, "Duplicate certificate in " + foundCert.getOrigins());
		}
		List<OrphanCertificateWrapper> orphanCertificates = foundCertificates.getOrphanCertificates();
		for (OrphanCertificateWrapper foundCert : orphanCertificates) {
			assertTrue(foundCert.getOrigins().size() < 2, "Duplicate certificate in " + foundCert.getOrigins());
		}
	}

	@Override
	protected void checkNoDuplicateCompleteRevocationData(FoundRevocationsProxy foundRevocations) {
		super.checkNoDuplicateCompleteRevocationData(foundRevocations);
		
		List<RelatedRevocationWrapper> relatedRevocations = foundRevocations.getRelatedRevocationData();
		for (RelatedRevocationWrapper foundRevocation : relatedRevocations) {
			assertTrue(foundRevocation.getOrigins().size() < 2, "Duplicate revocation data in " + foundRevocation.getOrigins());
		}
		List<OrphanRevocationWrapper> orphanRevocations = foundRevocations.getOrphanRevocationData();
		for (OrphanRevocationWrapper foundRevocation : orphanRevocations) {
			assertTrue(foundRevocation.getOrigins().size() < 2, "Duplicate revocation data in " + foundRevocation.getOrigins());
		}
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		List<String> signatureIdList = simpleReport.getSignatureIdList();
		for (String sigId : signatureIdList) {			
			CertificateToken certificate = getSigningCert();			
			String name = DSSASN1Utils.getHumanReadableName(certificate);
			assertEquals(name, simpleReport.getSignedBy(sigId));
		}
	}
	
	@Override
	protected void validateETSISignatureAttributes(SignatureAttributesType signatureAttributes) {
		validateETSISignatureAttributes(signatureAttributes, getSignatureParameters());
	}
	
	protected void validateETSISignatureAttributes(SignatureAttributesType signatureAttributes, SerializableSignatureParameters parameters) {
		assertNotNull(signatureAttributes);
		super.validateETSISignatureAttributes(signatureAttributes);

		List<JAXBElement<?>> signatureAttributeObjects = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
		for (JAXBElement<?> signatureAttributeObj : signatureAttributeObjects) {
			Object value = signatureAttributeObj.getValue();
			if (value instanceof SACommitmentTypeIndicationType) {
				// TODO multiple value -> multiple tag in signatureattributes ??
				SACommitmentTypeIndicationType commitment = (SACommitmentTypeIndicationType) value;
				validateETSICommitment(commitment, parameters);
			} else if (value instanceof SASignerRoleType) {
				SASignerRoleType signerRoles = (SASignerRoleType) value;
				validateETSISASignerRoleType(signerRoles, parameters);
			} else if (value instanceof SASignatureProductionPlaceType) {
				SASignatureProductionPlaceType productionPlace = (SASignatureProductionPlaceType) value;
				validateETSISASignatureProductionPlaceType(productionPlace, parameters);
			}
		}
	}
	
	protected void validateETSICommitment(SACommitmentTypeIndicationType commitment, SerializableSignatureParameters parameters) {
		List<CommitmentType> commitmentTypeIndications = parameters.bLevel().getCommitmentTypeIndications();
		List<String> uriList = commitmentTypeIndications.stream().map(CommitmentType::getUri).collect(Collectors.toList());
		List<String> oidList = commitmentTypeIndications.stream().map(c -> DSSUtils.getOidCode(c.getOid())).collect(Collectors.toList());
		assertTrue(uriList.contains(commitment.getCommitmentTypeIdentifier()) || oidList.contains(commitment.getCommitmentTypeIdentifier()));
	}

	protected void validateETSISASignerRoleType(SASignerRoleType signerRoles, SerializableSignatureParameters parameters) {
		List<SAOneSignerRoleType> roleDetails = signerRoles.getRoleDetails();

		List<String> claimedSignerRoles = parameters.bLevel().getClaimedSignerRoles();
		if (Utils.isCollectionNotEmpty(claimedSignerRoles)) {
			for (String claimedToBeFound : claimedSignerRoles) {
				boolean found = false;
				for (SAOneSignerRoleType saOneSignerRoleType : roleDetails) {
					if (EndorsementType.CLAIMED.equals(saOneSignerRoleType.getEndorsementType())
							&& claimedToBeFound.equals(saOneSignerRoleType.getRole())) {
						found = true;
						break;
					}
				}
				assertTrue(found);
			}
		}

		List<String> signedAssertions = parameters.bLevel().getSignedAssertions();
		if (Utils.isCollectionNotEmpty(signedAssertions)) {
			for (String signedAssertionToBeFound : signedAssertions) {
				boolean found = false;
				for (SAOneSignerRoleType saOneSignerRoleType : roleDetails) {
					if (EndorsementType.SIGNED.equals(saOneSignerRoleType.getEndorsementType())) {
						if (areSignedAssertionsEqual(signedAssertionToBeFound, saOneSignerRoleType.getRole())) {
							found = true;
							break;
						}
					}
				}
				assertTrue(found);
			}
		}
	}

	protected void validateETSISASignatureProductionPlaceType(SASignatureProductionPlaceType productionPlace, SerializableSignatureParameters parameters) {
		List<String> addressString = productionPlace.getAddressString();
		SignerLocation signerLocation = parameters.bLevel().getSignerLocation();
		if (signerLocation == null) {
			return;
		}

		String country = signerLocation.getCountry();
		if (country != null) {
			assertTrue(addressString.contains(country));
		}
		String locality = signerLocation.getLocality();
		if (locality != null) {
			assertTrue(addressString.contains(locality));
		}
		String postOfficeBoxNumber = signerLocation.getPostOfficeBoxNumber();
		if (postOfficeBoxNumber != null) {
			assertTrue(addressString.contains(postOfficeBoxNumber));
		}
		String postalCode = signerLocation.getPostalCode();
		if (postalCode != null) {
			assertTrue(addressString.contains(postalCode));
		}
		String stateOrProvince = signerLocation.getStateOrProvince();
		if (stateOrProvince != null) {
			assertTrue(addressString.contains(stateOrProvince));
		}
		String street = signerLocation.getStreetAddress();
		if (street != null) {
			assertTrue(addressString.contains(street));
		}
	}

	/**
	 * In some cases, PDF files finish with %%EOF + EOL and some other cases only
	 * %%EOF
	 * There's no technical way to extract the exact file ending.
	 */
	private boolean isOnlyTwoBytesDifferAtLastPosition(byte[] originalByteArray, byte[] retrievedByteArray) {
		int lengthOrigin = originalByteArray.length;
		int lengthRetrieved = retrievedByteArray.length;

		int min = Math.min(lengthOrigin, lengthRetrieved);
		if ((lengthOrigin - min > 2) || (lengthRetrieved - min > 2)) {
			return false;
		}

		for (int i = 0; i < min; i++) {
			if (originalByteArray[i] != retrievedByteArray[i]) {
				return false;
			}
		}

		return true;
	}
	
	private void assertDigestEqual(DSSDocument originalDocument, XmlSignerData signerData) {

		XmlDigestAlgoAndValue digestAlgoAndValue = signerData.getDigestAlgoAndValue();
		assertNotNull(digestAlgoAndValue);
		DigestAlgorithm digestAlgorithm = digestAlgoAndValue.getDigestMethod();
		assertNotNull(digestAlgorithm);
		
		List<DSSDocument> similarDocuments = buildCloseDocuments(originalDocument);
		boolean equals = false;
		for (DSSDocument documentToCompare : similarDocuments) {
			if (Arrays.equals(documentToCompare.getDigestValue(digestAlgorithm), digestAlgoAndValue.getDigestValue())) {
				equals = true;
				break;
			}
		}
		assertTrue(equals);
		
	}
	
	/**
	 * Documents can end with optional characters
	 * This method returns all possible cases of the originalDocument end string
	 */
	private List<DSSDocument> buildCloseDocuments(DSSDocument originalDocument) {
		List<DSSDocument> documentList = new ArrayList<>();
		documentList.add(originalDocument);
		documentList.add(getReducedDocument(originalDocument, 1));
		documentList.add(getReducedDocument(originalDocument, 2));
		documentList.add(getExpandedDocument(originalDocument, new byte[] {'\n'}));
		documentList.add(getExpandedDocument(originalDocument, new byte[] {'\r', '\n'}));
		documentList.add(getExpandedDocument(originalDocument, new byte[] {' ', '\r', '\n'}));
		documentList.add(getExpandedDocument(originalDocument, new byte[] {' ', '\n'}));
		return documentList;
	}
	
	private DSSDocument getReducedDocument(DSSDocument document, int bytesToRemove) {
		try (InputStream inputStream = document.openStream()) {
			byte[] originalBytes = Utils.toByteArray(inputStream);
			byte[] subarray = Utils.subarray(originalBytes, 0, originalBytes.length - bytesToRemove);
			return new InMemoryDocument(subarray);
		} catch (IOException e) {
			fail(e);
			return null;
		}
	}
	
	private DSSDocument getExpandedDocument(DSSDocument document, byte[] bytesToExpand) {
		try (InputStream inputStream = document.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			byte[] originalBytes = Utils.toByteArray(inputStream);
			baos.write(originalBytes);
			baos.write(bytesToExpand);
			return new InMemoryDocument(baos.toByteArray());
		} catch (IOException e) {
			fail(e);
			return null;
		}
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		super.verifyOriginalDocuments(validator, diagnosticData);

		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		for (String signatureId : signatureIdList) {
			
			SignatureWrapper signatureById = diagnosticData.getSignatureById(signatureId);
			if (signatureById.isCounterSignature()) {
				continue;
			}

			List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
			assertTrue(Utils.isCollectionNotEmpty(retrievedOriginalDocuments));
			
			List<DSSDocument> originalDocuments = getOriginalDocuments();
			for (DSSDocument original : originalDocuments) {
				boolean found = documentPresent(original, retrievedOriginalDocuments);

				if (!MimeTypeEnum.PDF.equals(original.getMimeType())) {
					assertTrue(found, "Unable to retrieve the original document " + original.getName());
				} else if (!found) {
					byte[] originalByteArray = DSSUtils.toByteArray(original);
					DSSDocument retrieved = retrievedOriginalDocuments.get(0);
					byte[] retrievedByteArray = DSSUtils.toByteArray(retrieved);
					assertTrue(isOnlyTwoBytesDifferAtLastPosition(originalByteArray, retrievedByteArray));
					
					SignatureWrapper signature = diagnosticData.getSignatureById(signatureId);
					List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
					assertNotNull(signatureScopes);
					assertEquals(1, signatureScopes.size());
					XmlSignerData signerData = signatureScopes.get(0).getSignerData();
					assertNotNull(signerData);
					assertDigestEqual(original, signerData);
				}
			}
		}
	}

	protected boolean documentPresent(DSSDocument original, List<DSSDocument> retrievedDocuments) {
		boolean found = false;
		String originalDigest = getDigest(original);
		for (DSSDocument retrieved : retrievedDocuments) {
			String retrievedDigest = getDigest(retrieved);
			if (Utils.areStringsEqual(originalDigest, retrievedDigest)) {
				found = true;
				break;
			}
		}
		return found;
	}

	protected String getDigest(DSSDocument doc) {
		byte[] byteArray = DSSUtils.toByteArray(doc);
		// LOG.info("Bytes : {}", new String(byteArray));
		return Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, byteArray));
	}
	
	protected String getCanonicalizationMethod() {
		// Inclusive by default
		return CanonicalizationMethod.INCLUSIVE;
	}

	protected FileDocument generateLargeFile() throws IOException {
		return generateLargeFile("large-file.bin");
	}

	protected FileDocument generateLargeFile(String filename) throws IOException {
		// -Dlarge.file.size.mb=...
		String fileSizeStr = System.getProperty("large.file.size.mb", "2048");
		final int fileSizeMB = Integer.parseInt(fileSizeStr);

		File file = new File("target/" + filename);

		byte[] data = getRandomByteArray(0x00FFFFFF); // ~16 MB
		int reachedSize = 0;
		int byteArraySizeMB = 16;
		try (FileOutputStream fos = new FileOutputStream(file)) {
			while (reachedSize < fileSizeMB) {
				fos.write(data);
				reachedSize += byteArraySizeMB;
				if (reachedSize + byteArraySizeMB > fileSizeMB) {
					byteArraySizeMB = fileSizeMB - reachedSize;
					data = getRandomByteArray(byteArraySizeMB);
				}
			}
		}

		return new FileDocument(file);
	}

	private byte[] getRandomByteArray(int size) {
		byte[] data = new byte[(int)size];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(data);
		return data;
	}

	protected abstract List<DSSDocument> getOriginalDocuments();

	protected abstract DSSDocument sign();

}
