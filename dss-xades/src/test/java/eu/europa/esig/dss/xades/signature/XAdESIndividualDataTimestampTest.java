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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.validationreport.jaxb.VOReferenceType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectRepresentationType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;
import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.Test;

import jakarta.xml.bind.JAXBElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESIndividualDataTimestampTest extends PKIFactoryAccess {

	private static final String FILE1 = "src/test/resources/sample.xml";
	private static final String FILE2 = "src/test/resources/sampleISO.xml";

	@Test
	public void multiDocsEnveloping() throws Exception {
		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		List<DSSDocument> docs = new ArrayList<>();
		DSSDocument fileToBeIndividualTimestamped = new FileDocument(FILE1);
		docs.add(fileToBeIndividualTimestamped);

		DSSDocument notIndividuallyTimestampedFile = new FileDocument(FILE2);
		docs.add(notIndividuallyTimestampedFile);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		Date currentTime = new Date();
		signatureParameters.bLevel().setSigningDate(currentTime);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		String usedCanonicalizationAlgo = Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS;
		
		// Instead of manual canicalization, the one defined in the timestamp is being used
		// byte[] docCanonicalized = DSSXMLUtils.canonicalize(usedCanonicalizationAlgo, DSSUtils.toByteArray(fileToBeIndividualTimestamped));
		// byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, docCanonicalized);

		// do not apply canonicalization, because base64 results to an octet-stream
		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, DSSUtils.toByteArray(fileToBeIndividualTimestamped));
		
		TimestampBinary bcTst = getAlternateGoodTsa().getTimeStampResponse(DigestAlgorithm.SHA256, digest);

		TimestampToken tst = new TimestampToken(bcTst.getBytes(), TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
		tst.setTimestampIncludes(Arrays.asList(new TimestampInclude("r-" + signatureParameters.getDeterministicId() + "-1", true))); // TODO
		tst.setCanonicalizationMethod(usedCanonicalizationAlgo);

		TimestampToken contentTimestamp = service.getContentTimestamp(docs, signatureParameters);

		signatureParameters.setContentTimestamps(Arrays.asList(tst, contentTimestamp));

		ToBeSigned toSign1 = service.getDataToSign(docs, signatureParameters);
		SignatureValue value = getToken().sign(toSign1, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument result = service.signDocument(docs, signatureParameters, value);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(result);
		DefaultSignatureProcessExecutor processExecutor = new DefaultSignatureProcessExecutor();
		validator.setValidationTime(currentTime);
		validator.setProcessExecutor(processExecutor);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, Utils.collectionSize(diagnosticData.getSignatureIdList()));

		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(2, Utils.collectionSize(signatureWrapper.getSignatureScopes()));

		List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
			assertTrue(timestamp.isSignatureValid());
		}

		TimestampWrapper individualDataTimestamp = timestampList.get(0);
		assertEquals(1, individualDataTimestamp.getTimestampScopes().size());
		assertEquals(1, individualDataTimestamp.getTimestampedObjects().size());

		TimestampWrapper allDataTimestamp = timestampList.get(1);
		assertEquals(2, allDataTimestamp.getTimestampScopes().size());
		assertEquals(2, allDataTimestamp.getTimestampedObjects().size());

		List<String> signatureCertificateChain = diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId());
		assertEquals(getCertificateChain().length, signatureCertificateChain.size());
		assertEquals(signatureParameters.getSignatureLevel(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));

		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		SignatureValidationReportType signatureValidationReportType = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReportType);

		SignersDocumentType signersDocuments = signatureValidationReportType.getSignersDocument();
		assertNotNull(signersDocuments);
		assertNull(getXmlDigestAlgoAndValue(signersDocuments));

		List<ValidationObjectType> validationObjects = getValidationObjects(signersDocuments);
		assertEquals(2, validationObjects.size());

		ValidationObjectRepresentationType validationObjectRepresentation = validationObjects.get(0).getValidationObjectRepresentation();
		assertEquals(1, validationObjectRepresentation.getDirectOrBase64OrDigestAlgAndValue().size());
		assertTrue(validationObjectRepresentation.getDirectOrBase64OrDigestAlgAndValue().get(0) instanceof DigestAlgAndValueType);
		DigestAlgAndValueType digestAlgAndValueFirstDoc = (DigestAlgAndValueType) validationObjectRepresentation.getDirectOrBase64OrDigestAlgAndValue().get(0);
		assertNotNull(digestAlgAndValueFirstDoc);
		assertNotNull(digestAlgAndValueFirstDoc.getDigestMethod());
		assertNotNull(digestAlgAndValueFirstDoc.getDigestValue());
		assertEquals(Utils.toBase64(digestAlgAndValueFirstDoc.getDigestValue()),
				fileToBeIndividualTimestamped.getDigest(DigestAlgorithm.forXML(digestAlgAndValueFirstDoc.getDigestMethod().getAlgorithm())));

		validationObjectRepresentation = validationObjects.get(1).getValidationObjectRepresentation();
		assertEquals(1, validationObjectRepresentation.getDirectOrBase64OrDigestAlgAndValue().size());
		assertTrue(validationObjectRepresentation.getDirectOrBase64OrDigestAlgAndValue().get(0) instanceof DigestAlgAndValueType);
		DigestAlgAndValueType digestAlgAndValueSecondDoc = (DigestAlgAndValueType) validationObjectRepresentation.getDirectOrBase64OrDigestAlgAndValue().get(0);
		assertNotNull(digestAlgAndValueSecondDoc);
		assertNotNull(digestAlgAndValueSecondDoc.getDigestMethod());
		assertNotNull(digestAlgAndValueSecondDoc.getDigestValue());
		assertEquals(Utils.toBase64(digestAlgAndValueSecondDoc.getDigestValue()),
				notIndividuallyTimestampedFile.getDigest(DigestAlgorithm.forXML(digestAlgAndValueSecondDoc.getDigestMethod().getAlgorithm())));

		ValidationObjectListType signatureValidationObjects = etsiValidationReport.getSignatureValidationObjects();
		assertNotNull(signatureValidationObjects);
		int timestampCounter = 0;
		int signedDataCounter = 0;
		for (ValidationObjectType validationObject : signatureValidationObjects.getValidationObject()) {
			assertNotNull(validationObject.getId());
			assertNotNull(validationObject.getObjectType());
			if (ObjectType.TIMESTAMP.equals(validationObject.getObjectType())) {
				assertNotNull(validationObject.getPOEProvisioning());
				assertNotNull(validationObject.getPOEProvisioning().getPOETime());
				assertTrue(Utils.isCollectionNotEmpty(validationObject.getPOEProvisioning().getValidationObject()));
				timestampCounter++;
			} else if (ObjectType.SIGNED_DATA.equals(validationObject.getObjectType())) {
				assertNotNull(validationObject.getPOE());
				Date poeTime = validationObject.getPOE().getPOETime();
				assertNotNull(poeTime);
				if (!poeTime.equals(currentTime)) {
					assertNotNull(validationObject.getPOE().getPOEObject());
				}
				assertNotNull(validationObject.getPOE().getTypeOfProof());
				signedDataCounter++;
			}
		}
		assertEquals(2, timestampCounter);
		assertEquals(2, signedDataCounter);

	}

	private DigestAlgAndValueType getXmlDigestAlgoAndValue(SignersDocumentType signersDocument) {
		for (JAXBElement<?> jaxbElement : signersDocument.getContent()) {
			Object value = jaxbElement.getValue();
			if (value instanceof DigestAlgAndValueType) {
				DigestAlgAndValueType digestAlgAndValueType = (DigestAlgAndValueType) value;
				assertNotNull(digestAlgAndValueType.getDigestMethod());
				assertNotNull(digestAlgAndValueType.getDigestValue());
				return digestAlgAndValueType;
			}
		}
		return null;
	}

	private List<ValidationObjectType> getValidationObjects(SignersDocumentType signersDocument) {
		List<ValidationObjectType> validationObjects = new ArrayList<>();
		for (JAXBElement<?> jaxbElement : signersDocument.getContent()) {
			Object value = jaxbElement.getValue();
			if (value instanceof VOReferenceType) {
				VOReferenceType voReferenceType = (VOReferenceType) value;
				List<Object> voReferences = voReferenceType.getVOReference();
				assertNotNull(voReferences);
				for (Object object : voReferences) {
					assertTrue(object instanceof ValidationObjectType);
					ValidationObjectType validationObjectType = (ValidationObjectType) object;
					assertEquals(ObjectType.SIGNED_DATA, validationObjectType.getObjectType());
					validationObjects.add(validationObjectType);
				}
			}
		}
		return validationObjects;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
