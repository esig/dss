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
package plugtests;

import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidator;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.OrphanCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.OfflineRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampTokenComparator;
import eu.europa.esig.dss.test.validation.AbstractDocumentTestValidation;
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.ValidationReportUtils;
import eu.europa.esig.validationreport.jaxb.SAContactInfoType;
import eu.europa.esig.validationreport.jaxb.SADSSType;
import eu.europa.esig.validationreport.jaxb.SAFilterType;
import eu.europa.esig.validationreport.jaxb.SAMessageDigestType;
import eu.europa.esig.validationreport.jaxb.SANameType;
import eu.europa.esig.validationreport.jaxb.SAReasonType;
import eu.europa.esig.validationreport.jaxb.SASubFilterType;
import eu.europa.esig.validationreport.jaxb.SAVRIType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static java.time.Duration.ofSeconds;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * This test is only to ensure that we don't have exception with valid? files
 */
class SignaturePoolTest extends AbstractDocumentTestValidation {
	
	private static final Logger LOG = LoggerFactory.getLogger(SignaturePoolTest.class);

	private static final String KEYSTORE_PATH = "src/main/resources/keystore.p12";
	private static final String KEYSTORE_TYPE = "PKCS12";
	private static final char[] KEYSTORE_PASSWORD = "dss-password".toCharArray();

	private static final String CACHE_PATH = "src/test/resources/signature-pool/cache";
	
	private static DSSDocument document;
	
	private static TrustedListsCertificateSource trustedCertSource;
	
	@BeforeAll
	static void init() throws Exception {
		// preload JAXB context before validation
		ValidationReportUtils.getInstance().getJAXBContext();
		
		trustedCertSource = new TrustedListsCertificateSource();
		
		TLValidationJob tlValidationJob = new TLValidationJob();
		tlValidationJob.setTrustedListCertificateSource(trustedCertSource);
		tlValidationJob.setSynchronizationStrategy(new AcceptAllStrategy());
		
		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setUrl("https://ec.europa.eu/tools/lotl/eu-lotl.xml");
		lotlSource.setCertificateSource(ojContentKeyStore());
		lotlSource.setPivotSupport(true);
		lotlSource.setTrustAnchorValidityPredicate(new GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate());
		lotlSource.setTLVersions(Arrays.asList(5, 6));

		tlValidationJob.setListOfTrustedListSources(lotlSource);
		
		FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
		fileCacheDataLoader.setFileCacheDirectory(new File(CACHE_PATH));
		fileCacheDataLoader.setCacheExpirationTime(-1);

		fileCacheDataLoader.setDataLoader(new IgnoreDataLoader());
		tlValidationJob.setOfflineDataLoader(fileCacheDataLoader);
		
		tlValidationJob.offlineRefresh();
		
		LOG.info("TrustedListsCertificateSource size : " + trustedCertSource.getNumberOfCertificates());
	}

	private static KeyStoreCertificateSource ojContentKeyStore() {
		try {
			return new KeyStoreCertificateSource(new File(KEYSTORE_PATH), KEYSTORE_TYPE, KEYSTORE_PASSWORD);
		} catch (IOException e) {
			throw new DSSException("Unable to load the file " + KEYSTORE_PATH, e);
		}
	}

	private static Stream<Arguments> data() {

		// -Dsignature.pool.folder=...

		String signaturePoolFolder = System.getProperty("signature.pool.folder", "src/test/resources/signature-pool");
		File folder = new File(signaturePoolFolder);
		Collection<File> listFiles = Utils.listFiles(folder, new String[] { "asice", "asics", "bdoc", "csig", "ddoc",
				"ers", "es3", "json", "p7", "p7b", "p7m", "p7s", "pdf", "pkcs7", "sce", "scs", "xml", "xsig" }, true);
		Collection<Arguments> dataToRun = new ArrayList<>();
		for (File file : listFiles) {
			dataToRun.add(Arguments.of(file));
		}
		return dataToRun.stream();
	}

	@ParameterizedTest(name = "Validation {index} : {0}")
	@MethodSource("data")
	void testValidate(File fileToTest) {
		LOG.info("Begin : {}", fileToTest.getAbsolutePath());
		document = new FileDocument(fileToTest);
		try {
			assertTimeout(ofSeconds(3L), () -> super.validate(), "Execution exceeded timeout for file " + fileToTest);
			LOG.info("End : {}", fileToTest.getAbsolutePath());
		} catch (Exception e) {
			fail("Validation of " + fileToTest + " failed", e);
		}
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setAIASource(null);
		certificateVerifier.setCrlSource(null);
		certificateVerifier.setOcspSource(null);
		certificateVerifier.setTrustedCertSources(trustedCertSource);
		validator.setCertificateVerifier(certificateVerifier);
		
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		signaturePolicyProvider.setDataLoader(null);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		
		return validator;
	}
	
	@Override
	public void validate() {
		// do nothing
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return document;
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		// do nothing
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		// skip the test
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.getDigestMatchers()));
		}
	}
	
	@Override
	protected void checkDigestAlgorithm(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.isSigningCertificateIdentified()) {
				assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.getDigestMatchers()));
			}
		}
	}
	
	@Override
	protected void checkEncryptionAlgorithm(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			if (signatureWrapper.isSigningCertificateIdentified()) {
				assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.getDigestMatchers()));
			}
		}
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
			if (signingCertificate != null) {
				String signingCertificateId = signingCertificate.getId();
				String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
				String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
				assertEquals(signingCertificate.getCertificateDN(), certificateDN);
				assertEquals(signingCertificate.getSerialNumber(), certificateSerialNumber);
				assertTrue(Utils.isCollectionNotEmpty(signatureWrapper.getCertificateChain()));
			}
		}
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNotNull(signatureWrapper.getSignatureFormat());
		}
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (timestampWrapper.getSigningCertificate() != null) {
				assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getCertificateChain()));
				if (timestampWrapper.isSignatureValid()) {
					assertNotNull(timestampWrapper.getDigestAlgorithm());
				}
			}
			if ((!timestampWrapper.getType().isContentTimestamp() && !timestampWrapper.getType().isDocumentTimestamp()
					&& !timestampWrapper.getType().isContainerTimestamp()) || timestampWrapper.isMessageImprintDataIntact()) {
				assertTrue(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedObjects()));
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
			assertNotNull(revocationWrapper.foundCertificates());
			assertNotNull(revocationWrapper.foundCertificates().getRelatedCertificates());
			assertNotNull(revocationWrapper.foundCertificates().getOrphanCertificates());

			if (revocationWrapper.getSigningCertificate() != null) {
				assertTrue(Utils.isCollectionNotEmpty(revocationWrapper.getCertificateChain()));

				if (RevocationType.OCSP.equals(revocationWrapper.getRevocationType())) {
					assertTrue(Utils.isCollectionNotEmpty(revocationWrapper.foundCertificates().getRelatedCertificates()));
					assertTrue(Utils.isCollectionNotEmpty(revocationWrapper.foundCertificates().getRelatedCertificateRefs()));

					assertTrue(revocationWrapper.isSigningCertificateReferencePresent());
					assertNotNull(revocationWrapper.getSigningCertificateReference());

					boolean signingCertFound = false;
					for (RelatedCertificateWrapper certificateWrapper : revocationWrapper.foundCertificates().getRelatedCertificates()) {
						for (CertificateRefWrapper refWrapper : certificateWrapper.getReferences()) {
							if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(refWrapper.getOrigin())) {
								signingCertFound = true;
							}
							assertTrue(refWrapper.getSki() != null || refWrapper.getIssuerName() != null);
							assertNull(refWrapper.getDigestAlgoAndValue());
							assertNull(refWrapper.getIssuerSerial());
						}
					}
					assertTrue(signingCertFound);
				}
			}
		}
	}

	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			for (XmlSignatureScope signatureScope : signatureWrapper.getSignatureScopes()) {
				assertNotNull(signatureScope.getScope());
				assertNotNull(signatureScope.getSignerData());
				assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue());
				assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestMethod());
				assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestValue());
			}
		}
	}
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNotNull(signatureWrapper.getSignatureValue());
		}
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		if (diagnosticData.getContainerInfo() != null) {
			assertNotNull(diagnosticData.getContainerType());
		}
	}
	
	@Override
	protected void checkSigningDate(DiagnosticData diagnosticData) {
		// do nothing
	}
	
	@Override
	protected void checkNoDuplicateSignatures(DiagnosticData diagnosticData) {
		// skip
	}

	@Override
	protected void checkCertificates(DiagnosticData diagnosticData) {
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			assertNotNull(certificateWrapper);
			assertNotNull(certificateWrapper.getId());
			assertNotNull(certificateWrapper.getCertificateDN());
			assertNotNull(certificateWrapper.getCertificateIssuerDN());
			assertNotNull(certificateWrapper.getNotAfter());
			assertNotNull(certificateWrapper.getNotBefore());
			assertTrue(Utils.isCollectionNotEmpty(certificateWrapper.getSources()));
			assertNotNull(certificateWrapper.getEntityKey());

			if (certificateWrapper.getSigningCertificate() != null) {
				assertNotNull(certificateWrapper.getEncryptionAlgorithm());
				assertNotNull(certificateWrapper.getKeyLengthUsedToSignThisToken());
				assertTrue(Utils.isStringDigits(certificateWrapper.getKeyLengthUsedToSignThisToken()));
				assertNotNull(certificateWrapper.getDigestAlgorithm());
				assertTrue(certificateWrapper.isSignatureIntact());
				assertTrue(certificateWrapper.isSignatureValid());
				assertNotNull(certificateWrapper.getIssuerEntityKey());
			} else if (certificateWrapper.isSelfSigned()) {
				assertNotNull(certificateWrapper.getEncryptionAlgorithm());
				assertNotNull(certificateWrapper.getKeyLengthUsedToSignThisToken());
				assertTrue(Utils.isStringDigits(certificateWrapper.getKeyLengthUsedToSignThisToken()));
				assertNotNull(certificateWrapper.getDigestAlgorithm());
				assertTrue(certificateWrapper.isSignatureIntact());
				assertTrue(certificateWrapper.isSignatureValid());
				assertNotNull(certificateWrapper.getIssuerEntityKey());
			}
		}
	}

	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        final TokenIdentifierProvider tokenIdentifierProvider = getTokenIdentifierProvider();

		for (AdvancedSignature advancedSignature : advancedSignatures) {
            SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(tokenIdentifierProvider.getIdAsString(advancedSignature));
            assertNotNull(signatureWrapper);

			SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
			FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();

			// Tokens
			assertEquals(new HashSet<>(certificateSource.getKeyInfoCertificates()).size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.KEY_INFO).size() + 
					foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.KEY_INFO).size());
			assertEquals(new HashSet<>(certificateSource.getCertificateValues()).size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size() + 
					foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
			assertEquals(new HashSet<>(certificateSource.getTimeStampValidationDataCertValues()).size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size() + 
					foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
			assertEquals(new HashSet<>(certificateSource.getAnyValidationDataCertValues()).size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size() +
							foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
			assertEquals(new HashSet<>(certificateSource.getAttrAuthoritiesCertValues()).size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES).size() +
					foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES).size());
			assertEquals(new HashSet<>(certificateSource.getSignedDataCertificates()).size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size() + 
					foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size());
			assertEquals(new HashSet<>(certificateSource.getDSSDictionaryCertValues()).size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size() + 
					foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size());
			assertEquals(new HashSet<>(certificateSource.getVRIDictionaryCertValues()).size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY).size() + 
					foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY).size());
			assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size() + 
					foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size());

			// Refs
			assertEquals(certificateSource.getSigningCertificateRefs().size(),
					getUniqueRelatedCertificateRefsAmount(foundCertificates, CertificateRefOrigin.SIGNING_CERTIFICATE) + 
					getUniqueOrphanCertificateRefsAmount(foundCertificates, CertificateRefOrigin.SIGNING_CERTIFICATE) );
			assertEquals(certificateSource.getAttributeCertificateRefs().size(),
					getUniqueRelatedCertificateRefsAmount(foundCertificates, CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS) + 
					getUniqueOrphanCertificateRefsAmount(foundCertificates, CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS) );
			assertEquals(certificateSource.getCompleteCertificateRefs().size(),
					getUniqueRelatedCertificateRefsAmount(foundCertificates, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS) + 
					getUniqueOrphanCertificateRefsAmount(foundCertificates, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS) );

			List<TimestampToken> timestamps = advancedSignature.getAllTimestamps();
            timestamps.sort(new TimestampTokenComparator()); // ensure the same order as in DD
			for (TimestampToken timestampToken : timestamps) {
                TimestampWrapper timestampWrapper = diagnosticData.getTimestampById(tokenIdentifierProvider.getIdAsString(timestampToken));
                assertNotNull(timestampWrapper);

				certificateSource = timestampToken.getCertificateSource();
				foundCertificates = timestampWrapper.foundCertificates();

				// Tokens
				assertEquals(new HashSet<>(certificateSource.getKeyInfoCertificates()).size(), 
						foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.KEY_INFO).size() + 
						foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.KEY_INFO).size());
				assertEquals(new HashSet<>(certificateSource.getCertificateValues()).size(),
						foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size() + 
						foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
				assertEquals(new HashSet<>(certificateSource.getTimeStampValidationDataCertValues()).size(), 
						foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size() + 
						foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.TIMESTAMP_VALIDATION_DATA).size());
				assertEquals(new HashSet<>(certificateSource.getAnyValidationDataCertValues()).size(),
						foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size() +
								foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.ANY_VALIDATION_DATA).size());
				assertEquals(new HashSet<>(certificateSource.getAttrAuthoritiesCertValues()).size(), 
						foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES).size() +
						foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES).size());
				assertEquals(new HashSet<>(certificateSource.getSignedDataCertificates()).size(),
						foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size() + 
						foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.SIGNED_DATA).size());
				assertEquals(new HashSet<>(certificateSource.getDSSDictionaryCertValues()).size(), 
						foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size() + 
						foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size());
				assertEquals(new HashSet<>(certificateSource.getVRIDictionaryCertValues()).size(), 
						foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY).size() + 
						foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY).size());
				assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size() + 
						foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size());

				// Refs
				assertEquals(certificateSource.getSigningCertificateRefs().size(),
						getUniqueRelatedCertificateRefsAmount(foundCertificates, CertificateRefOrigin.SIGNING_CERTIFICATE) + 
						getUniqueOrphanCertificateRefsAmount(foundCertificates, CertificateRefOrigin.SIGNING_CERTIFICATE) );
				assertEquals(certificateSource.getAttributeCertificateRefs().size(),
						getUniqueRelatedCertificateRefsAmount(foundCertificates, CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS) + 
						getUniqueOrphanCertificateRefsAmount(foundCertificates, CertificateRefOrigin.ATTRIBUTE_CERTIFICATE_REFS) );
				assertEquals(certificateSource.getCompleteCertificateRefs().size(),
						getUniqueRelatedCertificateRefsAmount(foundCertificates, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS) + 
						getUniqueOrphanCertificateRefsAmount(foundCertificates, CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS) );
			}

			OfflineRevocationSource<OCSP> ocspSource = advancedSignature.getOCSPSource();
			Set<RevocationToken<OCSP>> allRevocationTokens = ocspSource.getAllRevocationTokens();
			for (RevocationToken<OCSP> revocationToken : allRevocationTokens) {
				RevocationCertificateSource revocationCertificateSource = revocationToken.getCertificateSource();
				if (revocationCertificateSource != null) {
                    RevocationWrapper revocationWrapper = diagnosticData.getRevocationById(tokenIdentifierProvider.getIdAsString(revocationToken));
                    assertNotNull(revocationWrapper);

                    if (!containsRevocationsWithSameId(allRevocationTokens, revocationToken)) {
                        foundCertificates = revocationWrapper.foundCertificates();
                        assertEquals(revocationCertificateSource.getCertificates().size(),
                                foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size() +
                                        foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.BASIC_OCSP_RESP).size());
                    }
				}
			}
		}
	}

    private <T extends Revocation> boolean containsRevocationsWithSameId(Set<RevocationToken<T>> allRevocationTokens, RevocationToken<T> revocationToken) {
        String revocationId = getTokenIdentifierProvider().getIdAsString(revocationToken);
        Set<RevocationToken<?>> revocationSetCopy = new HashSet<>(allRevocationTokens);
        revocationSetCopy.remove(revocationToken);
        for (RevocationToken<?> token : revocationSetCopy) {
            TokenIdentifierProvider tokenIdentifierProvider = getTokenIdentifierProvider();
            if (revocationId.equals(tokenIdentifierProvider.getIdAsString(token))) {
                return true;
            }
        }
        return false;
    }
	
	private long getUniqueRelatedCertificateRefsAmount(FoundCertificatesProxy foundCertificates, CertificateRefOrigin refOrigin) {
		List<RelatedCertificateWrapper> certificates = foundCertificates.getRelatedCertificatesByRefOrigin(refOrigin);
		Set<CertificateRefWrapper> refsSet = new HashSet<>();
		for (RelatedCertificateWrapper certificateWrapper : certificates) {
			for (CertificateRefWrapper ref : certificateWrapper.getReferences()) {
				if (refOrigin.equals(ref.getOrigin())) {
					refsSet.add(ref);
				}
			}
		}
		return filterUniqueRefs(refsSet).size();
	}
	
	private long getUniqueOrphanCertificateRefsAmount(FoundCertificatesProxy foundCertificates, CertificateRefOrigin refOrigin) {
		List<OrphanCertificateWrapper> certificates = foundCertificates.getOrphanCertificatesByRefOrigin(refOrigin);
		Set<CertificateRefWrapper> refsSet = new HashSet<>();
		for (OrphanCertificateWrapper certificateWrapper : certificates) {
			for (CertificateRefWrapper ref : certificateWrapper.getReferences()) {
				if (refOrigin.equals(ref.getOrigin())) {
					refsSet.add(ref);
				}
			}
		}
		return filterUniqueRefs(refsSet).size();
	}
	
	private Set<CertificateRefWrapper> filterUniqueRefs(Collection<CertificateRefWrapper> certificateRefs) {
		Set<CertificateRefWrapper> refsSet = new HashSet<>();
		for (CertificateRefWrapper certRef : certificateRefs) {
			boolean found = false;
			for (CertificateRefWrapper currentCertRef : refsSet) {
				if (equal(certRef, currentCertRef)) {
					found = true;
					break;
				}
			}
			if (!found) {
				refsSet.add(certRef);
			}
		}
		return refsSet;
	}
	
	private boolean equal(CertificateRefWrapper certRefOne, CertificateRefWrapper certRefTwo) {
		if (certRefOne.getDigestAlgoAndValue() != null) {
			if (certRefTwo.getDigestAlgoAndValue() == null) {
				return false;
			}
			if (!certRefOne.getDigestAlgoAndValue().getDigestMethod().equals(certRefTwo.getDigestAlgoAndValue().getDigestMethod())) {
				return false;
			}
			if (!Arrays.equals(certRefOne.getDigestAlgoAndValue().getDigestValue(), certRefTwo.getDigestAlgoAndValue().getDigestValue())) {
				return false;
			}
		} else if (certRefTwo.getDigestAlgoAndValue() != null) {
			return false;
		}
		if (certRefOne.getIssuerName() != null) {
			if (!certRefOne.getIssuerName().equals(certRefTwo.getIssuerName())) {
				return false;
			}
		} else if (certRefTwo.getIssuerName() != null) {
			return false;
		}
		if (certRefOne.getIssuerSerial() != null) {
			if (!Arrays.equals(certRefOne.getIssuerSerial(), certRefTwo.getIssuerSerial())) {
				return false;
			}
		} else if (certRefTwo.getIssuerSerial() != null) {
			return false;
		}
		if (certRefOne.getSki() != null) {
			if (!Arrays.equals(certRefOne.getSki(), certRefTwo.getSki())) {
				return false;
			}
		} else if (certRefTwo.getSki() != null) {
			return false;
		}
		return true;
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		if (Utils.isCollectionNotEmpty(diagnosticData.getUsedCertificates())) {
			super.checkOrphanTokens(diagnosticData);
		}
	}

	@Override
	protected void checkStructureValidation(DiagnosticData diagnosticData) {
		// skip
	}

	@Override
	protected void checkDTBSR(DiagnosticData diagnosticData) {
		// can be null
	}

	@Override
	protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
		List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
		for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
			List<XmlDigestMatcher> digestMatchers = evidenceRecord.getDigestMatchers();
			assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
		}
	}

	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		for (String signatureId : signatureIdList) {
			SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
			if (diagnosticData.isBLevelTechnicallyValid(signatureId) && isNotInvalidManifest(validator)
					&& signsDocuments(diagnosticData) && !signatureWrapper.isCounterSignature()
					// a PDF signature can be incorporated within the first PDF's revision (no original content can be extracted)
					&& !((SignatureForm.PAdES.equals(diagnosticData.getSignatureFormat(signatureId).getSignatureForm())
									|| SignatureForm.PKCS7.equals(diagnosticData.getSignatureFormat(signatureId).getSignatureForm()))
			 				&& diagnosticData.getFirstSignatureId().equals(signatureId))) {
				List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);
				assertTrue(Utils.isCollectionNotEmpty(retrievedOriginalDocuments));
			}
		}
	}
	
	private boolean isNotInvalidManifest(SignedDocumentValidator validator) {
		if (validator instanceof ASiCContainerWithCAdESValidator) {
			ASiCContainerWithCAdESValidator asicValidator = (ASiCContainerWithCAdESValidator) validator;
			List<ManifestFile> manifestFiles = asicValidator.getManifestFiles();
			for (ManifestFile manifestFile : manifestFiles) {
				if (Utils.isCollectionEmpty(manifestFile.getEntries())) {
					return false;
				}
			}
		}
		return true;
	}
	
	private boolean signsDocuments(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			boolean containsDocumentDigestMatcher = false;
			for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
				DigestMatcherType type = digestMatcher.getType();
				if (!DigestMatcherType.KEY_INFO.equals(type) && !DigestMatcherType.REFERENCE.equals(type) && 
						!DigestMatcherType.SIGNED_PROPERTIES.equals(type) && !DigestMatcherType.XPOINTER.equals(type) && 
						!DigestMatcherType.SIGNATURE_PROPERTIES.equals(type) && !DigestMatcherType.COUNTER_SIGNATURE.equals(type)) {
					containsDocumentDigestMatcher = true;
					break;
				}
			}
			if (!containsDocumentDigestMatcher) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
		assertNotNull(signatureValidationStatus);
		assertNotNull(signatureValidationStatus.getMainIndication());
	}
	
	@Override
	protected void validateSignerInformation(SignerInformationType signerInformation) {
		if (signerInformation != null) {
			assertNotNull(signerInformation.getSignerCertificate());
			assertTrue(Utils.isStringNotEmpty(signerInformation.getSigner()));
		}
	}

	@Override
	protected void validateETSISignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
		assertNotNull(signatureIdentifier);
		assertNotNull(signatureIdentifier.getId());
		if (signatureIdentifier.getDigestAlgAndValue() != null) {
			assertNotNull(signatureIdentifier.getDigestAlgAndValue().getDigestMethod());
			assertNotNull(signatureIdentifier.getDigestAlgAndValue().getDigestValue());
		}
		assertNotNull(signatureIdentifier.getSignatureValue());
	}
	
	@Override
	protected void validateETSIMessageDigest(SAMessageDigestType md) {
		if (md != null) {
			assertTrue(Utils.isArrayNotEmpty(md.getDigest()));
		}
	}

	@Override
	protected void validateETSIFilter(SAFilterType filterType) {
		if (filterType != null) {
			assertTrue(Utils.isStringNotBlank(filterType.getFilter()));
		}
	}

	@Override
	protected void validateETSISubFilter(SASubFilterType subFilterType) {
		if (subFilterType != null) {
			assertTrue(Utils.isStringNotBlank(subFilterType.getSubFilterElement()));
		}
	}

	@Override
	protected void validateETSIContactInfo(SAContactInfoType contactTypeInfo) {
		if (contactTypeInfo != null) {
			assertTrue(Utils.isStringNotBlank(contactTypeInfo.getContactInfoElement()));
		}
	}

	@Override
	protected void validateETSISAReasonType(SAReasonType reasonType) {
		if (reasonType != null) {
			assertTrue(Utils.isStringNotBlank(reasonType.getReasonElement()));
		}
	}

	@Override
	protected void validateETSISAName(SANameType nameType) {
		if (nameType != null) {
			assertTrue(Utils.isStringNotBlank(nameType.getNameElement()));
		}
	}

	@Override
	protected void validateETSIDSSType(SADSSType dss) {
		if (dss != null) {
			assertTrue( (dss.getCerts() != null && Utils.isCollectionNotEmpty(dss.getCerts().getVOReference())) || 
					(dss.getCRLs() != null && Utils.isCollectionNotEmpty(dss.getCRLs().getVOReference())) || 
					(dss.getOCSPs() != null && Utils.isCollectionNotEmpty(dss.getOCSPs().getVOReference())) );
		}
	}

	@Override
	protected void validateETSIVRIType(SAVRIType vri) {
		if (vri != null) {
			assertTrue( (vri.getCerts() != null && Utils.isCollectionNotEmpty(vri.getCerts().getVOReference())) || 
					(vri.getCRLs() != null && Utils.isCollectionNotEmpty(vri.getCRLs().getVOReference())) || 
					(vri.getOCSPs() != null && Utils.isCollectionNotEmpty(vri.getOCSPs().getVOReference())) );
		}
	}
	
	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		// do nothing
	}
	
	@Override
	protected void checkReportsSignatureIdentifier(Reports reports) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		
		if (Utils.isCollectionNotEmpty(diagnosticData.getSignatures())) {
			for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
				SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());
				
				SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
				assertNotNull(signatureIdentifier);
				
				assertNotNull(signatureIdentifier.getSignatureValue());
				assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
			}
		}
	}

	@Override
	protected boolean allArchiveDataObjectsProvidedToValidation() {
		return false;
	}

	@Override
	protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
		// skip
	}

	@Override
	protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
		// skip
	}

}