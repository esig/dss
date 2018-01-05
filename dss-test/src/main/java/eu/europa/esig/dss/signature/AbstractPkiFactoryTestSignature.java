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

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
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

		try {
			byte[] byteArray = Utils.toByteArray(signedDocument.openStream());
			onDocumentSigned(byteArray);
			if (LOG.isDebugEnabled()) {
				LOG.debug(new String(byteArray));
			}
		} catch (Exception e) {
			LOG.error("Cannot display file content", e);
		}

		checkMimeType(signedDocument);

		Reports reports = getValidationReport(signedDocument);
		// reports.setValidateXml(true);
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		verifyDiagnosticData(diagnosticData);

		SimpleReport simpleReport = reports.getSimpleReport();
		verifySimpleReport(simpleReport);

		DetailedReport detailedReport = reports.getDetailedReport();
		verifyDetailedReport(detailedReport);
	}

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

	protected Reports getValidationReport(final DSSDocument signedDocument) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setSignaturePolicyProvider(getSignaturePolicyProvider());
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));

		Reports reports = validator.validateDocument();
		return reports;
	}

	protected SignaturePolicyProvider getSignaturePolicyProvider() {
		return null;
	}

	protected void checkMimeType(DSSDocument signedDocument) {
		assertEquals(getExpectedMime(), signedDocument.getMimeType());
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
		KSPrivateKeyEntry entry = getToken().getKey(getSigningAlias());
		List<String> signatureCertificateChain = diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId());
		assertTrue(Utils.isCollectionNotEmpty(signatureCertificateChain));
		// upper certificate than trust anchors are ignored
		assertTrue(entry.getCertificateChain().length >= signatureCertificateChain.size());
	}

	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertEquals(getSignatureParameters().getSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	protected void checkBLevelValid(DiagnosticData diagnosticData) {
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
			assertTrue(timestampWrapper.isSignatureValid());
			assertTrue(timestampWrapper.isSignatureIntact());
		}
	}

	protected boolean hasContentTimestamp() {
		return false;
	}

	protected void checkSigningDate(DiagnosticData diagnosticData) {
		Date signatureDate = diagnosticData.getFirstSignatureDate();
		Date originalSigningDate = getSignatureParameters().bLevel().getSigningDate();

		// Date in signed documents is truncated
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss");

		assertEquals(dateFormat.format(originalSigningDate), dateFormat.format(signatureDate));
	}

}
