/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.JAXBElement;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.stream.StreamResult;

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
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.jaxb.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDiagnosticData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignerData;
import eu.europa.esig.dss.jaxb.simplereport.SimpleReportFacade;
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
import eu.europa.esig.jaxb.validationreport.POEType;
import eu.europa.esig.jaxb.validationreport.SACertIDListType;
import eu.europa.esig.jaxb.validationreport.SACertIDType;
import eu.europa.esig.jaxb.validationreport.SACommitmentTypeIndicationType;
import eu.europa.esig.jaxb.validationreport.SAContactInfoType;
import eu.europa.esig.jaxb.validationreport.SADSSType;
import eu.europa.esig.jaxb.validationreport.SADataObjectFormatType;
import eu.europa.esig.jaxb.validationreport.SAFilterType;
import eu.europa.esig.jaxb.validationreport.SAMessageDigestType;
import eu.europa.esig.jaxb.validationreport.SANameType;
import eu.europa.esig.jaxb.validationreport.SAOneSignerRoleType;
import eu.europa.esig.jaxb.validationreport.SAReasonType;
import eu.europa.esig.jaxb.validationreport.SASignatureProductionPlaceType;
import eu.europa.esig.jaxb.validationreport.SASignerRoleType;
import eu.europa.esig.jaxb.validationreport.SASigningTimeType;
import eu.europa.esig.jaxb.validationreport.SASubFilterType;
import eu.europa.esig.jaxb.validationreport.SATimestampType;
import eu.europa.esig.jaxb.validationreport.SAVRIType;
import eu.europa.esig.jaxb.validationreport.SignatureAttributesType;
import eu.europa.esig.jaxb.validationreport.SignatureIdentifierType;
import eu.europa.esig.jaxb.validationreport.SignatureValidationReportType;
import eu.europa.esig.jaxb.validationreport.SignerInformationType;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;
import eu.europa.esig.jaxb.validationreport.ValidationStatusType;
import eu.europa.esig.jaxb.validationreport.ValidationTimeInfoType;
import eu.europa.esig.jaxb.validationreport.enums.EndorsementType;

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
		checkAdvancedSignatures(signatures);

		Reports reports = validator.validateDocument();
		// reports.setValidateXml(true);
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(reports.getXmlDiagnosticData());
		verifyDiagnosticData(diagnosticData);

		verifyDiagnosticDataJaxb(reports.getDiagnosticDataJaxb());

		SimpleReport simpleReport = reports.getSimpleReport();
		assertNotNull(reports.getXmlSimpleReport());
		verifySimpleReport(simpleReport);

		DetailedReport detailedReport = reports.getDetailedReport();
		assertNotNull(reports.getXmlDetailedReport());
		verifyDetailedReport(detailedReport);

		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		assertNotNull(reports.getXmlValidationReport());
		verifyETSIValidationReport(etsiValidationReportJaxb);

		getOriginalDocument(signedDocument, diagnosticData);

		generateHtmlPdfReports(reports);
	}

	protected void generateHtmlPdfReports(Reports reports) {
		if (!isGenerateHtmlPdfReports()) {
			return;
		}

		SimpleReportFacade simpleReportFacade = SimpleReportFacade.newFacade();

		String marshalledSimpleReport = null;
		try {
			marshalledSimpleReport = simpleReportFacade.marshall(reports.getSimpleReportJaxb(), true);
			assertNotNull(marshalledSimpleReport);
		} catch (Exception e) {
			String message = "Unable to marshall the simple report";
			LOG.error(message, e);
			fail(message);
		}

		try {
			assertNotNull(simpleReportFacade.generateHtmlReport(marshalledSimpleReport));
		} catch (Exception e) {
			String message = "Unable to generate the html simple report from the string source";
			LOG.error(message, e);
			fail(message);
		}

		try {
			assertNotNull(simpleReportFacade.generateHtmlReport(reports.getSimpleReportJaxb()));
		} catch (Exception e) {
			String message = "Unable to generate the html simple report from the jaxb source";
			LOG.error(message, e);
			fail(message);
		}

		try (StringWriter sw = new StringWriter()) {
			simpleReportFacade.generatePdfReport(marshalledSimpleReport, new StreamResult(sw));
			assertTrue(Utils.isStringNotBlank(sw.toString()));
		} catch (Exception e) {
			String message = "Unable to generate the pdf simple report from the string source";
			LOG.error(message, e);
			fail(message);
		}

		try (StringWriter sw = new StringWriter()) {
			simpleReportFacade.generatePdfReport(reports.getSimpleReportJaxb(), new StreamResult(sw));
			assertTrue(Utils.isStringNotBlank(sw.toString()));
		} catch (Exception e) {
			String message = "Unable to generate the pdf simple report from the jaxb source";
			LOG.error(message, e);
			fail(message);
		}

		DetailedReportFacade detailedReportFacade = DetailedReportFacade.newFacade();

		String marshalledDetailedReport = null;
		try {
			marshalledDetailedReport = detailedReportFacade.marshall(reports.getDetailedReportJaxb(), true);
			assertNotNull(marshalledDetailedReport);
		} catch (Exception e) {
			String message = "Unable to marshall the detailed report";
			LOG.error(message, e);
			fail(message);
		}

		try {
			assertNotNull(detailedReportFacade.generateHtmlReport(marshalledDetailedReport));
		} catch (Exception e) {
			String message = "Unable to generate the html detailed report from the string source";
			LOG.error(message, e);
			fail(message);
		}

		try {
			assertNotNull(detailedReportFacade.generateHtmlReport(reports.getDetailedReportJaxb()));
		} catch (Exception e) {
			String message = "Unable to generate the html detailed report from the jaxb source";
			LOG.error(message, e);
			fail(message);
		}

		try (StringWriter sw = new StringWriter()) {
			detailedReportFacade.generatePdfReport(marshalledDetailedReport, new StreamResult(sw));
			assertTrue(Utils.isStringNotBlank(sw.toString()));
		} catch (Exception e) {
			String message = "Unable to generate the pdf detailed report from the string source";
			LOG.error(message, e);
			fail(message);
		}

		try (StringWriter sw = new StringWriter()) {
			detailedReportFacade.generatePdfReport(reports.getDetailedReportJaxb(), new StreamResult(sw));
			assertTrue(Utils.isStringNotBlank(sw.toString()));
		} catch (Exception e) {
			String message = "Unable to generate the pdf detailed report from the jaxb source";
			LOG.error(message, e);
			fail(message);
		}

	}

	protected boolean isGenerateHtmlPdfReports() {
		return false;
	}

	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		assertTrue(Utils.isCollectionNotEmpty(signatures));
	}

	protected void getOriginalDocument(DSSDocument signedDocument, DiagnosticData diagnosticData) throws IOException {
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

	/**
	 * In some cases, PDF files finish with %%EOF + EOL and some other cases only
	 * %%EOF
	 * 
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
	
	private void assertDigestEqual(DSSDocument originalDocument, XmlSignerData signerData) throws IOException {

		XmlDigestAlgoAndValue digestAlgoAndValue = signerData.getDigestAlgoAndValue();
		assertNotNull(digestAlgoAndValue);
		DigestAlgorithm digestAlgorithm = DigestAlgorithm.forName(digestAlgoAndValue.getDigestMethod());
		assertNotNull(digestAlgorithm);
		
		List<DSSDocument> similarDocuments = buildCloseDocuments(originalDocument);
		boolean equals = false;
		for (DSSDocument documentToCompare : similarDocuments) {
			if (documentToCompare.getDigest(digestAlgorithm).equals(Utils.toBase64(digestAlgoAndValue.getDigestValue()))) {
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
	private List<DSSDocument> buildCloseDocuments(DSSDocument originalDocument) throws IOException {
		List<DSSDocument> documentList = new ArrayList<DSSDocument>();
		documentList.add(originalDocument);
		documentList.add(getReducedDocument(originalDocument, 1));
		documentList.add(getReducedDocument(originalDocument, 2));
		documentList.add(getExpandedDocument(originalDocument, new byte[] {'\n'}));
		documentList.add(getExpandedDocument(originalDocument, new byte[] {'\r', '\n'}));
		documentList.add(getExpandedDocument(originalDocument, new byte[] {' ', '\r', '\n'}));
		documentList.add(getExpandedDocument(originalDocument, new byte[] {' ', '\n'}));
		return documentList;
	}
	
	private DSSDocument getReducedDocument(DSSDocument document, int bytesToRemove) throws IOException {
		try (InputStream inputStream = document.openStream()) {
			byte[] originalBytes = Utils.toByteArray(inputStream);
			byte[] subarray = Utils.subarray(originalBytes, 0, originalBytes.length - bytesToRemove);
			return new InMemoryDocument(subarray);
		}
	}
	
	private DSSDocument getExpandedDocument(DSSDocument document, byte[] bytesToExpand) throws IOException {
		try (InputStream inputStream = document.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			byte[] originalBytes = Utils.toByteArray(inputStream);
			baos.write(originalBytes);
			baos.write(bytesToExpand);
			return new InMemoryDocument(baos.toByteArray());
		}
	}

	private String getDigest(DSSDocument doc, boolean toBeCanonicalized) {
		byte[] byteArray = DSSUtils.toByteArray(doc);
		if (toBeCanonicalized) {
			try {
				// we canonicalize to ignore the header (which is not covered by the signature)
				Canonicalizer c14n = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
				byteArray = c14n.canonicalize(byteArray);
			} catch (XMLSecurityException | ParserConfigurationException | IOException | SAXException e) {
				// Not always able to canonicalize (more than one file can be covered (XML +
				// something else) )
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
		checkClaimedRoles(diagnosticData);
		checkMessageDigestAlgorithm(diagnosticData);
		checkSignaturePolicyIdentifier(diagnosticData);
	}

	protected void verifyDiagnosticDataJaxb(XmlDiagnosticData diagnosticDataJaxb) {

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
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
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
		CertificateToken certificate = getPrivateKeyEntry().getCertificate();
		assertEquals(certificate.getSubjectX500Principal().getName(X500Principal.RFC2253), certificateDN);
		assertEquals(certificate.getSerialNumber().toString(), certificateSerialNumber);

		SignatureAlgorithm signatureAlgorithm = certificate.getSignatureAlgorithm();
		CertificateWrapper certificateWrapper = diagnosticData.getUsedCertificateById(signingCertificateId);
		assertEquals(signatureAlgorithm.getDigestAlgorithm(), certificateWrapper.getDigestAlgorithm());
		assertEquals(signatureAlgorithm.getEncryptionAlgorithm(), certificateWrapper.getEncryptionAlgorithm());

		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		for (SignatureWrapper signatureWrapper : allSignatures) {
			assertTrue(signatureWrapper.isSigningCertificateIdentified());
		}

	}

	protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
		String signingCertificateId = diagnosticData.getFirstSigningCertificateId();
		String issuerDN = diagnosticData.getCertificateIssuerDN(signingCertificateId);
		CertificateToken certificate = getPrivateKeyEntry().getCertificate();
		assertEquals(certificate.getIssuerX500Principal().getName(X500Principal.RFC2253), issuerDN);
	}

	protected void checkCertificateChain(DiagnosticData diagnosticData) {
		KSPrivateKeyEntry entry = getPrivateKeyEntry();
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

		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
		for (XmlDigestMatcher digestMatcher : digestMatchers) {
			assertTrue(digestMatcher.isDataFound());
			assertTrue(digestMatcher.isDataIntact());
		}

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

		int nbContentTimestamps = 0;
		boolean foundSignatureTimeStamp = false;
		boolean foundArchiveTimeStamp = false;

		if ((timestampIdList != null) && (timestampIdList.size() > 0)) {
			for (String timestampId : timestampIdList) {
				TimestampType timestampType = diagnosticData.getTimestampType(timestampId);
				switch (timestampType) {
					case CONTENT_TIMESTAMP:
					case ALL_DATA_OBJECTS_TIMESTAMP:
					case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
						nbContentTimestamps++;
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

		assertEquals(nbContentTimestamps, Utils.collectionSize(getSignatureParameters().getContentTimestamps()));

		if (isBaselineT()) {
			assertTrue(foundSignatureTimeStamp);
		}

		if (isBaselineLTA()) {
			assertTrue(foundArchiveTimeStamp);
		}

		Set<TimestampWrapper> allTimestamps = diagnosticData.getTimestampSet();
		for (TimestampWrapper timestampWrapper : allTimestamps) {
			assertNotNull(timestampWrapper.getProductionTime());
			assertTrue(timestampWrapper.isMessageImprintDataFound());
			assertTrue(timestampWrapper.isMessageImprintDataIntact());
			assertTrue(timestampWrapper.isSignatureIntact());
			assertTrue(timestampWrapper.isSignatureValid());

			List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
			for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
				assertTrue(xmlDigestMatcher.isDataFound());
				assertTrue(xmlDigestMatcher.isDataIntact());
			}
		}
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

	protected void checkClaimedRoles(DiagnosticData diagnosticData) {
		List<String> claimedRoles = getSignatureParameters().bLevel().getClaimedSignerRoles();
		if (Utils.isCollectionNotEmpty(claimedRoles)) {
			SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
			List<String> foundClaimedRoles = signatureWrapper.getClaimedRoles();
			assertTrue(claimedRoles.equals(foundClaimedRoles));
		}
	}

	protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
		DigestAlgorithm expectedDigestAlgorithm = getSignatureParameters().getReferenceDigestAlgorithm();
		if (expectedDigestAlgorithm == null) {
			expectedDigestAlgorithm = getSignatureParameters().getDigestAlgorithm();
		}

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertTrue(Utils.isCollectionNotEmpty(digestMatchers));
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			assertEquals(expectedDigestAlgorithm.getName(), xmlDigestMatcher.getDigestMethod());
		}
	}

	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
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
			if (Utils.isStringNotEmpty(signaturePolicy.getSpuri())) {
				assertEquals(signaturePolicy.getSpuri(), signature.getPolicyUrl());
			} else {
				assertTrue(Utils.isStringEmpty(signature.getPolicyUrl()));
			}
		}
	}

	protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {

		// Validation report is not signed
		assertNull(etsiValidationReportJaxb.getSignature());
		// Validation report is not generated by a TSP
		assertNull(etsiValidationReportJaxb.getSignatureValidator());

		List<SignatureValidationReportType> reports = etsiValidationReportJaxb.getSignatureValidationReport();
		for (SignatureValidationReportType signatureValidationReport : reports) {
			assertNotNull(signatureValidationReport);
			
			SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
			validateEtsiSignatureIdentifier(signatureIdentifier);

			SignerInformationType signerInformation = signatureValidationReport.getSignerInformation();
			assertNotNull(signerInformation);
			assertNotNull(signerInformation.getSignerCertificate());
			assertTrue(Utils.isStringNotEmpty(signerInformation.getSigner()));

			ValidationTimeInfoType validationTimeInfo = signatureValidationReport.getValidationTimeInfo();
			assertNotNull(validationTimeInfo.getValidationTime());
			POEType bestSignatureTime = validationTimeInfo.getBestSignatureTime();
			assertNotNull(bestSignatureTime);
			assertNotNull(bestSignatureTime.getPOETime());
			assertNotNull(bestSignatureTime.getTypeOfProof());

			ValidationStatusType signatureValidationStatus = signatureValidationReport.getSignatureValidationStatus();
			assertNotNull(signatureValidationStatus);
			assertNotNull(signatureValidationStatus.getMainIndication());

			SignatureAttributesType signatureAttributes = signatureValidationReport.getSignatureAttributes();
			validateETSISignatureAttributes(signatureAttributes);
		}
	}

	private void validateEtsiSignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
		assertNotNull(signatureIdentifier);
		assertNotNull(signatureIdentifier.getId());
		assertNotNull(signatureIdentifier.getDigestAlgAndValue());
		assertNotNull(signatureIdentifier.getDigestAlgAndValue().getDigestMethod());
		assertNotNull(signatureIdentifier.getDigestAlgAndValue().getDigestValue());
		assertNotNull(signatureIdentifier.getSignatureValue());
	}

	@SuppressWarnings("rawtypes")
	private void validateETSISignatureAttributes(SignatureAttributesType signatureAttributes) {
		List<Object> signatureAttributeObjects = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
		assertTrue(Utils.isCollectionNotEmpty(signatureAttributeObjects));

		for (Object signatureAttributeObj : signatureAttributeObjects) {
			if (signatureAttributeObj instanceof JAXBElement) {
				JAXBElement jaxbElement = (JAXBElement) signatureAttributeObj;
				Object value = jaxbElement.getValue();

				if (value instanceof SASigningTimeType) {
					SASigningTimeType signingTime = (SASigningTimeType) value;
					assertNotNull(signingTime.getTime());
				} else if (value instanceof SACertIDListType) {
					SACertIDListType certIdList = (SACertIDListType) value;
					List<SACertIDType> certIds = certIdList.getCertID();
					for (SACertIDType saCertIDType : certIds) {
						assertNotNull(saCertIDType.getDigestMethod());
						assertNotNull(saCertIDType.getDigestValue());
						assertNotNull(saCertIDType.getX509IssuerSerial());
					}
				} else if (value instanceof SADataObjectFormatType) {
					SADataObjectFormatType dataObjectFormatType = (SADataObjectFormatType) value;
					assertTrue((dataObjectFormatType.getContentType() != null) || (dataObjectFormatType.getMimeType() != null));
				} else if (value instanceof SACommitmentTypeIndicationType) {
					// TODO multiple value -> multiple tag in signatureattributes ??
					SACommitmentTypeIndicationType commitment = (SACommitmentTypeIndicationType) value;
					List<String> commitmentTypeIndications = getSignatureParameters().bLevel().getCommitmentTypeIndications();
					assertTrue(commitmentTypeIndications.contains(commitment.getCommitmentTypeIdentifier()));
				} else if (value instanceof SATimestampType) {
					SATimestampType timestamp = (SATimestampType) value;
					assertNotNull(timestamp.getAttributeObject());
					assertNotNull(timestamp.getTimeStampValue());

				} else if (value instanceof SASignatureProductionPlaceType) {
					SASignatureProductionPlaceType productionPlace = (SASignatureProductionPlaceType) value;
					validateETSISASignatureProductionPlaceType(productionPlace);

				} else if (value instanceof SASignerRoleType) {
					SASignerRoleType signerRoles = (SASignerRoleType) value;

					List<String> claimedSignerRoles = getSignatureParameters().bLevel().getClaimedSignerRoles();
					List<SAOneSignerRoleType> roleDetails = signerRoles.getRoleDetails();
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
				} else if (value instanceof SAMessageDigestType) {
					SAMessageDigestType md = (SAMessageDigestType) value;
					validateETSIMessageDigest(md);
				} else if (value instanceof SAReasonType) {
					SAReasonType reasonType = (SAReasonType) value;
					validateETSISAReasonType(reasonType);
				} else if (value instanceof SAFilterType) {
					SAFilterType filterType = (SAFilterType) value;
					validateETSIFilter(filterType);
				} else if (value instanceof SASubFilterType) {
					SASubFilterType subFilterType = (SASubFilterType) value;
					validateETSISubFilter(subFilterType);
				} else if (value instanceof SANameType) {
					SANameType nameType = (SANameType) value;
					validateETSISAName(nameType);
				} else if (value instanceof SAContactInfoType) {
					SAContactInfoType contactTypeInfo = (SAContactInfoType) value;
					validateETSIContactInfo(contactTypeInfo);
				} else if (value instanceof SADSSType) {
					SADSSType dss = (SADSSType) value;
					validateETSIDSSType(dss);
				} else if (value instanceof SAVRIType) {
					SAVRIType vri = (SAVRIType) value;
					validateETSIVRIType(vri);
				} else {
					LOG.warn("{} not tested", value.getClass());
				}

			} else {
				fail("Only JAXBElement are accepted");
			}
		}
	}

	protected void validateETSIMessageDigest(SAMessageDigestType md) {
		assertNotNull(md.getDigest());
	}

	protected void validateETSIFilter(SAFilterType filterType) {
		assertNull(filterType);
	}

	protected void validateETSISubFilter(SASubFilterType subFilterType) {
		assertNull(subFilterType);
	}

	protected void validateETSIContactInfo(SAContactInfoType contactTypeInfo) {
		assertNull(contactTypeInfo);
	}

	protected void validateETSISAReasonType(SAReasonType reasonType) {
		assertNull(reasonType);
	}

	protected void validateETSISAName(SANameType nameType) {
		assertNull(nameType);
	}

	protected void validateETSIDSSType(SADSSType dss) {
		assertNull(dss);
	}

	protected void validateETSIVRIType(SAVRIType vri) {
		assertNull(vri);
	}

	protected void validateETSISASignatureProductionPlaceType(SASignatureProductionPlaceType productionPlace) {
		List<String> addressString = productionPlace.getAddressString();
		SignerLocation signerLocation = getSignatureParameters().bLevel().getSignerLocation();

		String country = signerLocation.getCountry();
		if (country != null) {
			assertTrue(addressString.contains(country));
		}
		String locality = signerLocation.getLocality();
		if (locality != null) {
			assertTrue(addressString.contains(locality));
		}
		String postalCode = signerLocation.getPostalCode();
		if (postalCode != null) {
			assertTrue(addressString.contains(postalCode));
		}
		String stateOrProvince = signerLocation.getStateOrProvince();
		if (stateOrProvince != null) {
			assertTrue(addressString.contains(stateOrProvince));
		}
		String street = signerLocation.getStreet();
		if (street != null) {
			assertTrue(addressString.contains(street));
		}
	}

}
