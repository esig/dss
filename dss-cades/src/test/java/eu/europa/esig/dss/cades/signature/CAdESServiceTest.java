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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
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
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESServiceTest extends PKIFactoryAccess {
	
	private static DSSDocument documentToSign;
    private static CertificateVerifier certificateVerifier;
	private static CAdESService service;
	
	@BeforeEach
	void init() {
		documentToSign = new InMemoryDocument("Hello world!".getBytes());
        certificateVerifier = getCompleteCertificateVerifier();
        service = new CAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());
	}
	
	@Test
	void signatureTest() throws Exception {
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		
        Exception exception = assertThrows(NullPointerException.class, () -> signAndValidate(null, signatureParameters));
        assertEquals("toSignDocument cannot be null!", exception.getMessage());
		
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());
		
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());
        
        signatureParameters.setGenerateTBSWithoutCertificate(true);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Unsupported signature packaging: null", exception.getMessage());
        signatureParameters.setGenerateTBSWithoutCertificate(false);

        certificateVerifier.setAlertOnNotYetValidCertificate(new SilentOnStatusAlert());
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());
        
        signatureParameters.setSigningCertificate(getSigningCert());
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Unsupported signature packaging: null", exception.getMessage());
        
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());
        
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        exception = assertThrows(UnsupportedOperationException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Unsupported signature format 'XAdES-BASELINE-B' for extension.", exception.getMessage());
        
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signAndValidate(documentToSign, signatureParameters);
        
		BLevelParameters bLevel = signatureParameters.bLevel();
		exception = assertThrows(NullPointerException.class, () -> bLevel.setSigningDate(null));
        assertEquals("SigningDate cannot be null!", exception.getMessage());

        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setArchiveTimestampParameters(new CAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setBLevelParams(new BLevelParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setCertificateChain(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setCertificateChain((List<CertificateToken>)null);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setContentTimestampParameters(new CAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setDetachedContents(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignatureTimestampParameters(new CAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignedData(new byte[] {});
        signAndValidate(documentToSign, signatureParameters);
        
        exception = assertThrows(NullPointerException.class, () -> signatureParameters.setDigestAlgorithm(null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());
        
        signatureParameters.setContentHintsDescription(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setContentHintsType(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setContentIdentifierPrefix(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setContentIdentifierSuffix(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);
	}

    private DSSDocument signAndValidate(DSSDocument documentToSign, CAdESSignatureParameters signatureParameters) {
        DSSDocument signedDocument = sign(documentToSign, signatureParameters);
        assertNotNull(signedDocument);
        validate(signedDocument);
        return signedDocument;
	}
	
    private DSSDocument sign(DSSDocument documentToSign, CAdESSignatureParameters signatureParameters) {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
                getPrivateKeyEntry());
        return service.signDocument(documentToSign, signatureParameters, signatureValue);
    }

	@Test
	void extensionTest() {
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		DSSDocument signedDocument = signAndValidate(documentToSign, signatureParameters);
		
		CAdESSignatureParameters extensionParameters = new CAdESSignatureParameters();
		
        Exception exception = assertThrows(NullPointerException.class, () -> extendAndValidate(null, extensionParameters));
        assertEquals("toExtendDocument is not defined!", exception.getMessage());
		
        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, null));
        assertEquals("Cannot extend the signature. SignatureParameters are not defined!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());
        
        extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        exception = assertThrows(UnsupportedOperationException.class, () ->  extendAndValidate(signedDocument, extensionParameters));
        assertEquals("Unsupported signature format 'XAdES-BASELINE-B' for extension.", exception.getMessage());
        
        extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        exception = assertThrows(UnsupportedOperationException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("Unsupported signature format 'CAdES-BASELINE-B' for extension.", exception.getMessage());
        
        extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        extendAndValidate(signedDocument, extensionParameters);
	}

    @Test
    void addSignaturePolicyStoreTest() {
        CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

        DSSDocument signaturePolicy = new InMemoryDocument("Hello world!".getBytes());
        Policy policy = new Policy();
        policy.setId("1.2.3.4.5");
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
	
	private void extendAndValidate(DSSDocument documentToExtend, CAdESSignatureParameters signatureParameters) {
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
