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
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.DocumentBuilderFactory;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESServiceTest extends PKIFactoryAccess {
	
	private static DSSDocument documentToSign;
	private static XAdESService service;
	
	@BeforeEach
	public void init() {
		documentToSign = new FileDocument("src/test/resources/sample.xml");
        service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
	}
	
	@Test
	public void signatureTest() throws Exception {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		
        Exception exception = assertThrows(NullPointerException.class, () -> signAndValidate((DSSDocument) null, signatureParameters));
        assertEquals("toSignDocument cannot be null!", exception.getMessage());
		
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());
		
        exception = assertThrows(DSSException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined!", exception.getMessage());
        
        signatureParameters.setGenerateTBSWithoutCertificate(true);
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Cannot create a SignatureBuilder. SignaturePackaging is not defined!", exception.getMessage());
        signatureParameters.setGenerateTBSWithoutCertificate(false);

		signatureParameters.setSignWithNotYetValidCertificate(true);
		exception = assertThrows(DSSException.class, () -> signAndValidate(documentToSign, signatureParameters));
		assertEquals("Signing Certificate is not defined!", exception.getMessage());

        signatureParameters.setSignWithExpiredCertificate(true);
        exception = assertThrows(DSSException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined!", exception.getMessage());
        
        signatureParameters.setSigningCertificate(getSigningCert());
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Cannot create a SignatureBuilder. SignaturePackaging is not defined!", exception.getMessage());
        
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());
        
        exception = assertThrows(IllegalArgumentException.class, () -> signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B));
        assertEquals("Only XAdES form is allowed !", exception.getMessage());
        
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signAndValidate(documentToSign, signatureParameters);
        
		BLevelParameters bLevel = signatureParameters.bLevel();
		exception = assertThrows(NullPointerException.class, () -> bLevel.setSigningDate(null));
        assertEquals("SigningDate cannot be null!", exception.getMessage());

        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setArchiveTimestampParameters(new XAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setBLevelParams(new BLevelParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setCertificateChain(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setCertificateChain((List<CertificateToken>)null);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setContentTimestampParameters(new XAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setDetachedContents(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setReferences(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setRootDocument(DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignatureTimestampParameters(new XAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignedAdESObject(new byte[] {});
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignedData(new byte[] {});
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setXPathLocationString(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        exception = assertThrows(NullPointerException.class, () -> signatureParameters.setSigningCertificateDigestMethod(null));
        assertEquals("SigningCertificateDigestMethod cannot be null!", exception.getMessage());
        
        exception = assertThrows(NullPointerException.class, () -> signatureParameters.setDigestAlgorithm(null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());
        
        exception = assertThrows(IllegalArgumentException.class, () -> signatureParameters.setKeyInfoCanonicalizationMethod(null));
        assertEquals("Canonicalization cannot be empty! See EN 319 132-1: 3.1.2 Signature Generation.", exception.getMessage());
        
        exception = assertThrows(IllegalArgumentException.class, () -> signatureParameters.setSignedInfoCanonicalizationMethod(""));
        assertEquals("Canonicalization cannot be empty! See EN 319 132-1: 3.1.2 Signature Generation.", exception.getMessage());
        
        exception = assertThrows(IllegalArgumentException.class, () -> signatureParameters.setSignedPropertiesCanonicalizationMethod(null));
        assertEquals("Canonicalization cannot be empty! See EN 319 132-1: 3.1.2 Signature Generation.", exception.getMessage());
	}
	
	private DSSDocument signAndValidate(DSSDocument documentToSign, XAdESSignatureParameters signatureParameters) {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		assertNotNull(signedDocument);
		validate(signedDocument);
		return signedDocument;
	}

	@Test
	public void multipleDocumentsSignatureTest() throws Exception {
		DSSDocument documentToSign1 = new InMemoryDocument("Hello World!".getBytes());
		DSSDocument documentToSign2 = new InMemoryDocument("Bye World.".getBytes());

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();

		Exception exception = assertThrows(NullPointerException.class,
				() -> signAndValidate((List<DSSDocument>) null, signatureParameters));
		assertEquals("toSignDocuments cannot be null!", exception.getMessage());

		exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, null));
		assertEquals("SignatureParameters cannot be null!", exception.getMessage());

		final List<DSSDocument> documents = Arrays.asList(documentToSign1, documentToSign2);
		exception = assertThrows(NullPointerException.class, () -> signAndValidate(documents, signatureParameters));
		assertEquals("SignaturePackaging shall be defined!", exception.getMessage());

		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		exception = assertThrows(DSSException.class, () -> signAndValidate(documents, signatureParameters));
		assertEquals("All documents in the list to be signed shall have names!", exception.getMessage());

		documentToSign1.setName("doc");
		documentToSign2.setName("doc");
		final List<DSSDocument> docsWithName = Arrays.asList(documentToSign1, documentToSign2);
		exception = assertThrows(DSSException.class, () -> signAndValidate(docsWithName, signatureParameters));
		assertEquals("The documents to be signed shall have different names! "
				+ "The name 'doc' appears multiple times.", exception.getMessage());
		
		documentToSign2.setName("anotherDoc");
		exception = assertThrows(DSSException.class, () -> signAndValidate(documentToSign, signatureParameters));
		assertEquals("Signing Certificate is not defined!", exception.getMessage());

		signatureParameters.setSigningCertificate(getSigningCert());
		exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
		assertEquals("SignatureLevel must be defined!", exception.getMessage());

		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signAndValidate(documentToSign, signatureParameters);
	}

	private DSSDocument signAndValidate(List<DSSDocument> documentsToSign, XAdESSignatureParameters signatureParameters) {
		ToBeSigned dataToSign = service.getDataToSign(documentsToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentsToSign, signatureParameters, signatureValue);
        assertNotNull(signedDocument);
        validate(signedDocument);
        return signedDocument;
	}
	
	@Test
	public void extensionTest() {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		DSSDocument signedDocument = signAndValidate(documentToSign, signatureParameters);
		
		XAdESSignatureParameters extensionParameters = new XAdESSignatureParameters();
		
        Exception exception = assertThrows(NullPointerException.class, () -> extendAndValidate(null, extensionParameters));
        assertEquals("toExtendDocument is not defined!", exception.getMessage());
		
        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, null));
        assertEquals("Cannot extend the signature. SignatureParameters are not defined!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());
        
        exception = assertThrows(IllegalArgumentException.class, () ->  extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B));
        assertEquals("Only XAdES form is allowed !", exception.getMessage());
        
        extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        exception = assertThrows(DSSException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("Cannot extend to XAdES_BASELINE_B", exception.getMessage());
        
        extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        extendAndValidate(signedDocument, extensionParameters);
	}
	
	@Test
	public void contentTstTest() throws Exception {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		InMemoryDocument emptyBinaryDoc = new InMemoryDocument(new byte[]{});
		Exception exception = assertThrows(NullPointerException.class, () -> 
				service.getContentTimestamp(emptyBinaryDoc, signatureParameters));
		assertEquals("SignaturePackaging must be defined!", exception.getMessage());
		
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		assertNotNull(service.getContentTimestamp(new InMemoryDocument(new byte[] {}), signatureParameters));
		
		signatureParameters.setContentTimestampParameters(null);
		assertNotNull(service.getContentTimestamp(new InMemoryDocument(new byte[] {}), signatureParameters));
		
		XAdESTimestampParameters timestampParameters = new XAdESTimestampParameters();
		exception = assertThrows(IllegalArgumentException.class, () -> timestampParameters.setCanonicalizationMethod(null));
		assertEquals("Canonicalization cannot be empty! See EN 319 132-1: 4.5 Managing canonicalization of XML nodesets.", exception.getMessage());
		
		exception = assertThrows(IllegalArgumentException.class, () -> timestampParameters.setCanonicalizationMethod(""));
		assertEquals("Canonicalization cannot be empty! See EN 319 132-1: 4.5 Managing canonicalization of XML nodesets.", exception.getMessage());
		
		InMemoryDocument document = new InMemoryDocument("Hello World!".getBytes());
		
		timestampParameters.setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
		signatureParameters.setContentTimestampParameters(timestampParameters);
		TimestampToken contentTimestamp = service.getContentTimestamp(document, signatureParameters);
		
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		contentTimestamp.setCanonicalizationMethod(null);
		signatureParameters.setContentTimestamps(Arrays.asList(contentTimestamp));

		exception = assertThrows(DSSException.class, () -> service.getDataToSign(document, signatureParameters));
		assertEquals("Unable to create a timestamp with empty canonicalization method. "
				+ "See EN 319 132-1: 4.5 Managing canonicalization of XML nodesets.", exception.getMessage());
	}
	
	private void extendAndValidate(DSSDocument documentToExtend, XAdESSignatureParameters signatureParameters) {
		DSSDocument extendedDocument = service.extendDocument(documentToExtend, signatureParameters);
        assertNotNull(extendedDocument);
        validate(extendedDocument);
	}
	
	private void validate(DSSDocument documentToValidate) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToValidate);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());
        Reports reports = validator.validateDocument();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        for (TimestampWrapper timestamp : timestampList) {
        	assertTrue(timestamp.isSignatureValid());
        	assertTrue(timestamp.isSignatureIntact());
        	assertTrue(timestamp.isMessageImprintDataFound());
        	assertTrue(timestamp.isMessageImprintDataIntact());
        }
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
