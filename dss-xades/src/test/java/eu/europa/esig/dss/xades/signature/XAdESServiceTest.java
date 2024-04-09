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

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.CommonCommitmentType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESServiceTest extends PKIFactoryAccess {
	
	private static DSSDocument documentToSign;
	private static CertificateVerifier certificateVerifier;
	private static XAdESService service;
	
	@BeforeEach
	public void init() {
		documentToSign = new FileDocument("src/test/resources/sample.xml");
		certificateVerifier = getCompleteCertificateVerifier();
        service = new XAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());
	}
	
	@Test
	public void signatureTest() throws Exception {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		
        Exception exception = assertThrows(NullPointerException.class, () -> signAndValidate((DSSDocument) null, signatureParameters));
        assertEquals("toSignDocument cannot be null!", exception.getMessage());
		
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());
		
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());
        
        signatureParameters.setGenerateTBSWithoutCertificate(true);
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Cannot create a SignatureBuilder. SignaturePackaging is not defined!", exception.getMessage());
        signatureParameters.setGenerateTBSWithoutCertificate(false);

		certificateVerifier.setAlertOnNotYetValidCertificate(new SilentOnStatusAlert());
		exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
		assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

		certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
		exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
		assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());
        
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

		BLevelParameters bLevelParameters = new BLevelParameters();
		signatureParameters.setBLevelParams(bLevelParameters);
        signAndValidate(documentToSign, signatureParameters);

		CommonCommitmentType commitmentType = new CommonCommitmentType();
		bLevelParameters.setCommitmentTypeIndications(Collections.singletonList(commitmentType));

		exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
		assertEquals("The URI or OID must be defined for commitmentTypeIndication for XAdES creation!", exception.getMessage());

		commitmentType.setUri("http://nowina.lu/approval");
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
        
        signatureParameters.setRootDocument(DomUtils.getSecureDocumentBuilderFactory()
				.newDocumentBuilder().newDocument());
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
		DSSDocument signedDocument = sign(documentToSign, signatureParameters);
		assertNotNull(signedDocument);
		validate(signedDocument);
		return signedDocument;
	}

	private DSSDocument sign(DSSDocument documentToSign, XAdESSignatureParameters signatureParameters) {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		return service.signDocument(documentToSign, signatureParameters, signatureValue);
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
		exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documents, signatureParameters));
		assertEquals("All documents in the list to be signed shall have names!", exception.getMessage());

		documentToSign1.setName("doc");
		documentToSign2.setName("doc");
		final List<DSSDocument> docsWithName = Arrays.asList(documentToSign1, documentToSign2);
		exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(docsWithName, signatureParameters));
		assertEquals("The documents to be signed shall have different names! The name 'doc' appears multiple times.", exception.getMessage());
		
		documentToSign2.setName("anotherDoc");
		exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
		assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

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
        assertEquals("toExtendDocument cannot be null!", exception.getMessage());
		
        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, null));
        assertEquals("Cannot extend the signature. SignatureParameters are not defined!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());
        
        exception = assertThrows(IllegalArgumentException.class, () ->  extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B));
        assertEquals("Only XAdES form is allowed !", exception.getMessage());
        
        extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        exception = assertThrows(UnsupportedOperationException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("Unsupported signature format 'XAdES-BASELINE-B' for extension.", exception.getMessage());
        
        extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        extendAndValidate(signedDocument, extensionParameters);
	}
	
	@Test
	public void contentTstTest() throws Exception {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		InMemoryDocument emptyBinaryDoc = InMemoryDocument.createEmptyDocument();
		Exception exception = assertThrows(NullPointerException.class, () -> 
				service.getContentTimestamp(emptyBinaryDoc, signatureParameters));
		assertEquals("SignaturePackaging must be defined!", exception.getMessage());
		
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		assertNotNull(service.getContentTimestamp(InMemoryDocument.createEmptyDocument(), signatureParameters));
		
		signatureParameters.setContentTimestampParameters(null);
		assertNotNull(service.getContentTimestamp(InMemoryDocument.createEmptyDocument(), signatureParameters));
		
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

		exception = assertThrows(IllegalArgumentException.class, () -> service.getDataToSign(document, signatureParameters));
		assertEquals("Unable to create a timestamp with empty canonicalization method. "
				+ "See EN 319 132-1: 4.5 Managing canonicalization of XML nodesets.", exception.getMessage());
	}
	
	private void extendAndValidate(DSSDocument documentToExtend, XAdESSignatureParameters signatureParameters) {
		DSSDocument extendedDocument = service.extendDocument(documentToExtend, signatureParameters);
        assertNotNull(extendedDocument);
        validate(extendedDocument);
	}

	@Test
	public void addSignaturePolicyStoreTest() {
		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		DSSDocument signaturePolicy = new InMemoryDocument("Hello world!".getBytes());
		Policy policy = new Policy();
		policy.setId("Policy Id");
		policy.setDigestAlgorithm(DigestAlgorithm.SHA256);
		policy.setDigestValue(signaturePolicy.getDigestValue(DigestAlgorithm.SHA256));
		signatureParameters.bLevel().setSignaturePolicy(policy);

		DSSDocument signedDocument = sign(documentToSign, signatureParameters);

		Exception exception = assertThrows(NullPointerException.class,
				() -> service.addSignaturePolicyStore(null, null));
		assertEquals("The document cannot be null", exception.getMessage());

		exception = assertThrows(NullPointerException.class,
				() -> service.addSignaturePolicyStore(signedDocument, null));
		assertEquals("The signaturePolicyStore cannot be null", exception.getMessage());

		SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();

		exception = assertThrows(NullPointerException.class,
				() -> service.addSignaturePolicyStore(signedDocument, signaturePolicyStore));
		assertEquals("SpDocSpecification must be provided", exception.getMessage());

		SpDocSpecification spDocSpecification = new SpDocSpecification();
		signaturePolicyStore.setSpDocSpecification(spDocSpecification);

		exception = assertThrows(NullPointerException.class,
				() -> service.addSignaturePolicyStore(signedDocument, signaturePolicyStore));
		assertEquals("ID (OID or URI) for SpDocSpecification must be provided", exception.getMessage());

		spDocSpecification.setId("Policy-Id");

		exception = assertThrows(IllegalArgumentException.class,
				() -> service.addSignaturePolicyStore(signedDocument, signaturePolicyStore));
		assertEquals("SignaturePolicyStore shall contain either SignaturePolicyContent document or sigPolDocLocalURI!", exception.getMessage());

		signaturePolicyStore.setSignaturePolicyContent(new InMemoryDocument("Bye world!".getBytes()));

		exception = assertThrows(IllegalInputException.class,
				() -> service.addSignaturePolicyStore(signedDocument, signaturePolicyStore));
		assertEquals("The process did not find a signature to add SignaturePolicyStore!", exception.getMessage());

		signaturePolicyStore.setSignaturePolicyContent(signaturePolicy);

		DSSDocument documentWithPolicy = service.addSignaturePolicyStore(signedDocument, signaturePolicyStore);
		assertNotNull(documentWithPolicy);

		validate(documentWithPolicy);

		signaturePolicyStore.setSigPolDocLocalURI("/local/path/policy.xml");

		exception = assertThrows(IllegalArgumentException.class,
				() -> service.addSignaturePolicyStore(signedDocument, signaturePolicyStore));
		assertEquals("SignaturePolicyStore shall contain either SignaturePolicyContent document or sigPolDocLocalURI!", exception.getMessage());

		signaturePolicyStore.setSignaturePolicyContent(null);

		documentWithPolicy = service.addSignaturePolicyStore(signedDocument, signaturePolicyStore);
		assertNotNull(documentWithPolicy);
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
