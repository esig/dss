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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.xml.security.c14n.Canonicalizer;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.CustomProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.jaxb.validationreport.SignatureValidationReportType;
import eu.europa.esig.jaxb.validationreport.SignersDocumentType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectListType;
import eu.europa.esig.jaxb.validationreport.ValidationObjectType;
import eu.europa.esig.jaxb.validationreport.ValidationReportType;
import eu.europa.esig.jaxb.validationreport.enums.ObjectType;
import eu.europa.esig.jaxb.xades132.DigestAlgAndValueType;

public class XAdESIndividualDataTimestampTest extends PKIFactoryAccess {

	private static String FILE1 = "src/test/resources/sample.xml";
	private static String FILE2 = "src/test/resources/sampleISO.xml";

	@Test
	public void multiDocsEnveloping() throws Exception {
		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		List<DSSDocument> docs = new ArrayList<DSSDocument>();
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
		byte[] docCanonicalized = DSSXMLUtils.canonicalize(usedCanonicalizationAlgo, DSSUtils.toByteArray(fileToBeIndividualTimestamped));

		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, docCanonicalized);
		TimeStampToken bcTst = getAlternateGoodTsa().getTimeStampResponse(DigestAlgorithm.SHA256, digest);

		TimestampToken tst = new TimestampToken(bcTst, TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);
		tst.setTimestampIncludes(Arrays.asList(new TimestampInclude("r-" + signatureParameters.getDeterministicId() + "-1", true))); // TODO
		tst.setCanonicalizationMethod(usedCanonicalizationAlgo);

		TimestampToken contentTimestamp = service.getContentTimestamp(docs, signatureParameters);

		signatureParameters.setContentTimestamps(Arrays.asList(tst, contentTimestamp));

		ToBeSigned toSign1 = service.getDataToSign(docs, signatureParameters);
		SignatureValue value = getToken().sign(toSign1, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument result = service.signDocument(docs, signatureParameters, value);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(result);
		CustomProcessExecutor processExecutor = new CustomProcessExecutor();
		processExecutor.setCurrentTime(currentTime);
		validator.setProcessExecutor(processExecutor);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

//		reports.print();

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

		assertEquals(1, timestampList.get(0).getTimestampedObjects().size());
		assertEquals(2, timestampList.get(1).getTimestampedObjects().size());

		List<String> signatureCertificateChain = diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId());
		assertEquals(getCertificateChain().length, signatureCertificateChain.size());
		assertEquals(signatureParameters.getSignatureLevel().toString(), diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));

		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		SignatureValidationReportType signatureValidationReportType = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReportType);
		List<SignersDocumentType> signersDocuments = signatureValidationReportType.getSignersDocument();
		assertNotNull(signersDocuments);
		assertEquals(2, signersDocuments.size());

		assertNotNull(signersDocuments.get(0));
		DigestAlgAndValueType digestAlgAndValueFirstDoc = signersDocuments.get(0).getDigestAlgAndValue();
		assertNotNull(digestAlgAndValueFirstDoc);
		assertNotNull(digestAlgAndValueFirstDoc.getDigestMethod());
		assertNotNull(digestAlgAndValueFirstDoc.getDigestValue());
		assertEquals(Utils.toBase64(digestAlgAndValueFirstDoc.getDigestValue()),
				fileToBeIndividualTimestamped.getDigest(DigestAlgorithm.forXML(digestAlgAndValueFirstDoc.getDigestMethod().getAlgorithm())));

		assertNotNull(signersDocuments.get(1));
		DigestAlgAndValueType digestAlgAndValueSecondDoc = signersDocuments.get(1).getDigestAlgAndValue();
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

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
