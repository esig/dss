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
package eu.europa.esig.dss.asic.cades.signature;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCWithCAdESServiceTest extends PKIFactoryAccess {
	
	private static DSSDocument documentToSign;
	private static ASiCWithCAdESService service;
	
	@BeforeEach
	public void init() {
		documentToSign = new InMemoryDocument("Hello world!".getBytes());
        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
	}
	
	@Test
	public void signatureTest() throws Exception {
		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		
        Exception exception = assertThrows(NullPointerException.class, () -> signAndValidate(null, signatureParameters));
        assertEquals("toSignDocument cannot be null!", exception.getMessage());
		
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

        signatureParameters.setSignWithExpiredCertificate(true);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

        signatureParameters.setGenerateTBSWithoutCertificate(true);
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("ASiCContainerType must be defined!", exception.getMessage());

        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());

        signatureParameters.setGenerateTBSWithoutCertificate(false);
        exception = assertThrows(IllegalArgumentException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());
        
        signatureParameters.setSigningCertificate(getSigningCert());
        exception = assertThrows(NullPointerException.class, () -> signAndValidate(documentToSign, signatureParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());
        
        exception = assertThrows(IllegalArgumentException.class, () -> signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B));
        assertEquals("Only CAdES form is allowed !", exception.getMessage());
        
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signAndValidate(documentToSign, signatureParameters);
        
		BLevelParameters bLevel = signatureParameters.bLevel();
		exception = assertThrows(NullPointerException.class, () -> bLevel.setSigningDate(null));
        assertEquals("SigningDate cannot be null!", exception.getMessage());

        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setArchiveTimestampParameters(new CAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setArchiveTimestampParameters(new ASiCWithCAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setBLevelParams(new BLevelParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setCertificateChain(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setCertificateChain((List<CertificateToken>)null);
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setContentTimestampParameters(new CAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setContentTimestampParameters(new ASiCWithCAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setDetachedContents(Collections.emptyList());
        signAndValidate(documentToSign, signatureParameters);

        signatureParameters.setSignatureTimestampParameters(new CAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignatureTimestampParameters(new ASiCWithCAdESTimestampParameters());
        signAndValidate(documentToSign, signatureParameters);
        
        signatureParameters.setSignedData(new byte[] {});
        signAndValidate(documentToSign, signatureParameters);
        
        exception = assertThrows(NullPointerException.class, () -> signatureParameters.setDigestAlgorithm(null));
        assertEquals("DigestAlgorithm cannot be null!", exception.getMessage());
        
        signatureParameters.aSiC().setMimeType(Utils.EMPTY_STRING);
        signAndValidate(documentToSign, signatureParameters);

	}
	
	private DSSDocument signAndValidate(DSSDocument documentToSign, ASiCWithCAdESSignatureParameters signatureParameters) throws IOException {
        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
        // signedDocument.save("target/signed.asice");
        assertNotNull(signedDocument);
        validate(signedDocument);
        return signedDocument;
	}
	
	@Test
	public void extensionTest() throws IOException {
		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
		DSSDocument signedDocument = signAndValidate(documentToSign, signatureParameters);
		
		ASiCWithCAdESSignatureParameters extensionParameters = new ASiCWithCAdESSignatureParameters();
		
        Exception exception = assertThrows(NullPointerException.class, () -> extendAndValidate(null, extensionParameters));
        assertEquals("toExtendDocument is not defined!", exception.getMessage());
		
        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, null));
        assertEquals("Cannot extend the signature. SignatureParameters are not defined!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("SignatureLevel must be defined!", exception.getMessage());
        
        exception = assertThrows(IllegalArgumentException.class, () ->  extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B));
        assertEquals("Only CAdES form is allowed !", exception.getMessage());
        
        extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        exception = assertThrows(UnsupportedOperationException.class, () -> extendAndValidate(signedDocument, extensionParameters));
        assertEquals("Unsupported signature format 'CAdES-BASELINE-B' for extension.", exception.getMessage());
        
        extensionParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        extendAndValidate(signedDocument, extensionParameters);
	}
	
	private void extendAndValidate(DSSDocument documentToExtend, ASiCWithCAdESSignatureParameters signatureParameters) {
		DSSDocument extendedDocument = service.extendDocument(documentToExtend, signatureParameters);
        assertNotNull(extendedDocument);
        validate(extendedDocument);
	}
	
	private void validate(DSSDocument documentToValidate) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToValidate);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());
        Reports reports = validator.validateDocument();
        // reports.print();
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
