package eu.europa.esig.dss.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.TimestampType;

public abstract class AbstractPkiFactoryTestSignature<SP extends AbstractSignatureParameters> extends PKIFactoryAccess {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractPkiFactoryTestSignature.class);

	protected abstract SP getSignatureParameters();

	protected abstract MimeType getExpectedMime();

	protected abstract boolean isBaselineT();

	protected abstract boolean isBaselineLTA();

	@Test
	public void signAndVerify() throws IOException {
		final DSSDocument signedDocument = sign();

		assertNotNull(signedDocument.getName());
		assertNotNull(DSSUtils.toByteArray(signedDocument));
		assertNotNull(signedDocument.getMimeType());

		LOG.info("=================== VALIDATION =================");

		// signedDocument.save("target/" + signedDocument.getName());

		byte[] byteArray = DSSUtils.toByteArray(signedDocument);
		onDocumentSigned(byteArray);
		if (LOG.isDebugEnabled()) {
			LOG.debug(new String(byteArray));
		}

		checkMimeType(signedDocument);

		SignedDocumentValidator validator = getValidator(signedDocument);

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));

		Reports reports = validator.validateDocument();
		// reports.setValidateXml(true);
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		verifyDiagnosticData(diagnosticData);

		SimpleReport simpleReport = reports.getSimpleReport();
		verifySimpleReport(simpleReport);

		DetailedReport detailedReport = reports.getDetailedReport();
		verifyDetailedReport(detailedReport);

		getOriginalDocument(signedDocument, diagnosticData);
	}

	protected void getOriginalDocument(DSSDocument signedDocument, DiagnosticData diagnosticData) {
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		for (String signatureId : signatureIdList) {

			SignedDocumentValidator validator = getValidator(signedDocument);
			List<DSSDocument> retrievedOriginalDocuments = validator.getOriginalDocuments(signatureId);

			assertTrue(Utils.isCollectionNotEmpty(retrievedOriginalDocuments));
			List<DSSDocument> originalDocuments = getOriginalDocuments();

			for (DSSDocument original : originalDocuments) {
				boolean found = false;
				boolean toBeCanonicalized = MimeType.XML.equals(original.getMimeType()) || MimeType.HTML.equals(original.getMimeType());
				String originalDigest = getDigest(original, toBeCanonicalized);
				for (DSSDocument retrieved : retrievedOriginalDocuments) {
					String retrievedDigest = getDigest(retrieved, toBeCanonicalized);
					if (Utils.areStringsEqual(originalDigest, retrievedDigest)) {
						found = true;
					}
				}

				if (!MimeType.PDF.equals(original.getMimeType())) {
					assertTrue("Unable to retrieve the document " + original.getName(), found);
				} else if (!found) {
					byte[] originalByteArray = DSSUtils.toByteArray(original);
					DSSDocument retrieved = retrievedOriginalDocuments.get(0);
					byte[] retrievedByteArray = DSSUtils.toByteArray(retrieved);
					assertTrue(isOnlyOneByteDifferAtLastPosition(originalByteArray, retrievedByteArray));
				}
			}
		}
	}

	/**
	 * In some cases, PDF files finish with %%EOF + EOL and some other cases only %%EOF
	 * 
	 * There's no technical way to extract the exact file ending.
	 */
	private boolean isOnlyOneByteDifferAtLastPosition(byte[] originalByteArray, byte[] retrievedByteArray) {
		int lengthOrigin = originalByteArray.length;
		int lengthRetrieved = retrievedByteArray.length;

		int min = Math.min(lengthOrigin, lengthRetrieved);
		if ((lengthOrigin - min > 1) || (lengthRetrieved - min > 1)) {
			return false;
		}

		for (int i = 0; i < min; i++) {
			if (originalByteArray[i] != retrievedByteArray[i]) {
				return false;
			}
		}

		return true;
	}

	private String getDigest(DSSDocument doc, boolean toBeCanonicalized) {
		byte[] byteArray = DSSUtils.toByteArray(doc);
		if (toBeCanonicalized) {
			try {
				// we canonicalize to ignore the header (which is not covered by the signature)
				Canonicalizer c14n = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
				byteArray = c14n.canonicalize(byteArray);
			} catch (XMLSecurityException | ParserConfigurationException | IOException | SAXException e) {
				// Not always able to canonicalize (more than one file can be covered (XML + something else) )
			}
		}
		// LOG.info("Bytes : {}", new String(byteArray));
		return Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, byteArray));
	}

	protected abstract List<DSSDocument> getOriginalDocuments();

	protected abstract DSSDocument sign();

	protected void onDocumentSigned(byte[] byteArray) {
	}

	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		checkBLevelValid(diagnosticData);
		checkNumberOfSignatures(diagnosticData);
		checkDigestAlgorithm(diagnosticData);
		checkMaskGenerationFunction(diagnosticData);
		checkEncryptionAlgorithm(diagnosticData);
		checkSigningCertificateValue(diagnosticData);
		checkIssuerSigningCertificateValue(diagnosticData);
		checkCertificateChain(diagnosticData);
		checkSignatureLevel(diagnosticData);
		checkSigningDate(diagnosticData);
		checkTLevelAndValid(diagnosticData);
		checkALevelAndValid(diagnosticData);
		checkTimestamps(diagnosticData);
		checkSignatureScopes(diagnosticData);
		checkCommitmentTypeIndications(diagnosticData);
	}

	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
	}

	protected void verifySimpleReport(SimpleReport simpleReport) {
		assertNotNull(simpleReport);

		List<String> signatureIdList = simpleReport.getSignatureIdList();
		assertTrue(Utils.isCollectionNotEmpty(signatureIdList));

		for (String sigId : signatureIdList) {
			Indication indication = simpleReport.getIndication(sigId);
			assertNotNull(indication);
			if (indication != Indication.TOTAL_PASSED) {
				assertNotNull(simpleReport.getSubIndication(sigId));
			}
			assertNotNull(simpleReport.getSignatureQualification(sigId));
		}
		assertNotNull(simpleReport.getValidationTime());
	}

	protected void verifyDetailedReport(DetailedReport detailedReport) {
		assertNotNull(detailedReport);

		int nbBBBs = detailedReport.getBasicBuildingBlocksNumber();
		assertTrue(nbBBBs > 0);
		for (int i = 0; i < nbBBBs; i++) {
			String id = detailedReport.getBasicBuildingBlocksSignatureId(i);
			assertNotNull(id);
			assertNotNull(detailedReport.getBasicBuildingBlocksIndication(id));
		}

		List<String> signatureIds = detailedReport.getSignatureIds();
		assertTrue(Utils.isCollectionNotEmpty(signatureIds));
		for (String sigId : signatureIds) {
			Indication basicIndication = detailedReport.getBasicValidationIndication(sigId);
			assertNotNull(basicIndication);
			if (!Indication.PASSED.equals(basicIndication)) {
				assertNotNull(detailedReport.getBasicValidationSubIndication(sigId));
			}
		}

		if (isBaselineT()) {
			List<String> timestampIds = detailedReport.getTimestampIds();
			assertTrue(Utils.isCollectionNotEmpty(timestampIds));
			for (String tspId : timestampIds) {
				Indication timestampIndication = detailedReport.getTimestampValidationIndication(tspId);
				assertNotNull(timestampIndication);
				if (!Indication.PASSED.equals(timestampIndication)) {
					assertNotNull(detailedReport.getTimestampValidationSubIndication(tspId));
				}
			}
		}

		for (String sigId : signatureIds) {
			Indication ltvIndication = detailedReport.getLongTermValidationIndication(sigId);
			assertNotNull(ltvIndication);
			if (!Indication.PASSED.equals(ltvIndication)) {
				assertNotNull(detailedReport.getLongTermValidationSubIndication(sigId));
			}
		}

		for (String sigId : signatureIds) {
			Indication archiveDataIndication = detailedReport.getArchiveDataValidationIndication(sigId);
			assertNotNull(archiveDataIndication);
			if (!Indication.PASSED.equals(archiveDataIndication)) {
				assertNotNull(detailedReport.getArchiveDataValidationSubIndication(sigId));
			}
		}
	}

	protected SignedDocumentValidator getValidator(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setSignaturePolicyProvider(getSignaturePolicyProvider());
		return validator;
	}

	protected SignaturePolicyProvider getSignaturePolicyProvider() {
		return null;
	}

	protected void checkMimeType(DSSDocument signedDocument) {
		assertTrue(getExpectedMime().equals(signedDocument.getMimeType()));
	}

	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));
	}

	protected void checkDigestAlgorithm(DiagnosticData diagnosticData) {
		assertEquals(getSignatureParameters().getDigestAlgorithm(), diagnosticData.getSignatureDigestAlgorithm(diagnosticData.getFirstSignatureId()));
	}

	private void checkMaskGenerationFunction(DiagnosticData diagnosticData) {
		MaskGenerationFunction maskGenerationFunction = getSignatureParameters().getMaskGenerationFunction();
		if (maskGenerationFunction != null) {
			assertEquals(maskGenerationFunction, diagnosticData.getSignatureMaskGenerationFunction(diagnosticData.getFirstSignatureId()));
		}
	}

	private void checkEncryptionAlgorithm(DiagnosticData diagnosticData) {
		assertEquals(getSignatureParameters().getSignatureAlgorithm().getEncryptionAlgorithm(),
				diagnosticData.getSignatureEncryptionAlgorithm(diagnosticData.getFirstSignatureId()));
	}

	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		String signingCertificateId = diagnosticData.getFirstSigningCertificateId();
		String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
		String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
		CertificateToken certificate = getToken().getKey(getSigningAlias()).getCertificate();
		assertEquals(certificate.getSubjectX500Principal().getName(X500Principal.RFC2253), certificateDN);
		assertEquals(certificate.getSerialNumber().toString(), certificateSerialNumber);

		SignatureAlgorithm signatureAlgorithm = certificate.getSignatureAlgorithm();
		CertificateWrapper certificateWrapper = diagnosticData.getUsedCertificateById(signingCertificateId);
		assertEquals(signatureAlgorithm.getDigestAlgorithm(), certificateWrapper.getDigestAlgorithm());
		assertEquals(signatureAlgorithm.getEncryptionAlgorithm(), certificateWrapper.getEncryptionAlgorithm());
	}

	protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
		String signingCertificateId = diagnosticData.getFirstSigningCertificateId();
		String issuerDN = diagnosticData.getCertificateIssuerDN(signingCertificateId);
		CertificateToken certificate = getToken().getKey(getSigningAlias()).getCertificate();
		assertEquals(certificate.getIssuerX500Principal().getName(X500Principal.RFC2253), issuerDN);
	}

	protected void checkCertificateChain(DiagnosticData diagnosticData) {
		KSPrivateKeyEntry entry = (KSPrivateKeyEntry) getToken().getKey(getSigningAlias());
		List<String> signatureCertificateChain = diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId());
		assertTrue(Utils.isCollectionNotEmpty(signatureCertificateChain));
		// upper certificate than trust anchors are ignored
		assertTrue(entry.getCertificateChain().length >= signatureCertificateChain.size());
	}

	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertEquals(getSignatureParameters().getSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureWrapper.isReferenceDataFound());
		assertTrue(signatureWrapper.isReferenceDataIntact());
		assertTrue(signatureWrapper.isSignatureIntact());
		assertTrue(signatureWrapper.isSignatureValid());
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	protected void checkTLevelAndValid(DiagnosticData diagnosticData) {
		assertEquals(isBaselineT(), diagnosticData.isThereTLevel(diagnosticData.getFirstSignatureId()));
		assertEquals(isBaselineT(), diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	protected void checkALevelAndValid(DiagnosticData diagnosticData) {
		assertEquals(isBaselineLTA(), diagnosticData.isThereALevel(diagnosticData.getFirstSignatureId()));
		assertEquals(isBaselineLTA(), diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<String> timestampIdList = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());

		boolean foundContentTimeStamp = false;
		boolean foundSignatureTimeStamp = false;
		boolean foundArchiveTimeStamp = false;

		if ((timestampIdList != null) && (timestampIdList.size() > 0)) {
			for (String timestampId : timestampIdList) {
				String timestampType = diagnosticData.getTimestampType(timestampId);
				TimestampType type = TimestampType.valueOf(timestampType);
				switch (type) {
				case CONTENT_TIMESTAMP:
				case ALL_DATA_OBJECTS_TIMESTAMP:
				case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
					foundContentTimeStamp = true;
					break;
				case SIGNATURE_TIMESTAMP:
					foundSignatureTimeStamp = true;
					break;
				case ARCHIVE_TIMESTAMP:
					foundArchiveTimeStamp = true;
					break;
				default:
					break;
				}
			}
		}

		if (hasContentTimestamp()) {
			assertTrue(foundContentTimeStamp);
		}

		if (isBaselineT()) {
			assertTrue(foundSignatureTimeStamp);
		}

		if (isBaselineLTA()) {
			assertTrue(foundArchiveTimeStamp);
		}

		Set<TimestampWrapper> allTimestamps = diagnosticData.getAllTimestamps();
		for (TimestampWrapper timestampWrapper : allTimestamps) {
			assertNotNull(timestampWrapper.getProductionTime());
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			assertTrue(timestampWrapper.isSignatureIntact());
			assertTrue(timestampWrapper.isSignatureValid());
		}
	}

	protected boolean hasContentTimestamp() {
		return Utils.isCollectionNotEmpty(getSignatureParameters().getContentTimestamps());
	}

	protected void checkSigningDate(DiagnosticData diagnosticData) {
		Date signatureDate = diagnosticData.getFirstSignatureDate();
		Date originalSigningDate = getSignatureParameters().bLevel().getSigningDate();

		// Date in signed documents is truncated
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss");

		assertEquals(dateFormat.format(originalSigningDate), dateFormat.format(signatureDate));
	}

	protected void checkCommitmentTypeIndications(DiagnosticData diagnosticData) {
		List<String> commitmentTypeIndications = getSignatureParameters().bLevel().getCommitmentTypeIndications();
		if (Utils.isCollectionNotEmpty(commitmentTypeIndications)) {
			SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
			List<String> foundCommitmentTypeIdentifiers = signatureWrapper.getCommitmentTypeIdentifiers();
			assertTrue(commitmentTypeIndications.equals(foundCommitmentTypeIdentifiers));
		}
	}

}
