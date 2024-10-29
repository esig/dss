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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PAdESCRLSource;
import eu.europa.esig.dss.pades.validation.PAdESCertificateSource;
import eu.europa.esig.dss.pades.validation.PAdESOCSPSource;
import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class PAdESNoDuplicateValidationDataTest extends PKIFactoryAccess {
	
	@Test
	void test() throws IOException {
		
		DSSDocument toBeSigned = new InMemoryDocument(PAdESNoDuplicateValidationDataTest.class.getResourceAsStream("/sample.pdf"));

		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters params = new PAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		params.setSigningCertificate(getSigningCert());

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);
		
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(commonCertificateVerifier);
		
		Collection<PdfObjectKey> crlKeys = getCRLKeys(validator);
		Collection<PdfObjectKey> ocspKeys = getOCSPKeys(validator);
		Collection<PdfObjectKey> certKeys = getCertKeys(validator);
		
		checkValidationData(signedDocument, crlKeys, ocspKeys, certKeys, true);
		
		DSSDocument extendedDocument = service.extendDocument(signedDocument, params);
		checkValidationData(extendedDocument, crlKeys, ocspKeys, certKeys, true);
		
		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		checkValidationData(doubleSignedDocument, crlKeys, ocspKeys, certKeys, false);
		
		DSSDocument doubleSignedExtendedDocument = service.extendDocument(signedDocument, params);
		checkValidationData(doubleSignedExtendedDocument, crlKeys, ocspKeys, certKeys, true);
		
		// doubleSignedExtendedDocument.save("target/doubleSigned.pdf");
		
	}
	
	private Collection<PdfObjectKey> getCRLKeys(SignedDocumentValidator validator) {
		Collection<PdfObjectKey> crls = new ArrayList<>();
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			PAdESCRLSource crlSource = (PAdESCRLSource) signature.getCRLSource();
			crls.addAll(crlSource.getCrlMap().keySet());
		}
		return crls;
	}
	
	private Collection<PdfObjectKey> getOCSPKeys(SignedDocumentValidator validator) {
		Collection<PdfObjectKey> ocsps = new ArrayList<>();
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			PAdESOCSPSource ocspSource = (PAdESOCSPSource) signature.getOCSPSource();
			ocsps.addAll(ocspSource.getOcspMap().keySet());
		}
		return ocsps;
	}
	
	private Collection<PdfObjectKey> getCertKeys(SignedDocumentValidator validator) {
		Collection<PdfObjectKey> certs = new ArrayList<>();
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			PAdESCertificateSource certificateSource = (PAdESCertificateSource) signature.getCertificateSource();
			certs.addAll(certificateSource.getCertificateMap().keySet());
		}
		return certs;
	}
	
	private void checkValidationData(DSSDocument document, Collection<PdfObjectKey> crls, Collection<PdfObjectKey> ocsps, Collection<PdfObjectKey> certs, boolean match) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			PAdESCRLSource crlSource = (PAdESCRLSource) signature.getCRLSource();
			Map<PdfObjectKey, CRLBinary> crlMap = crlSource.getCrlMap();
			if (match) {
				assertEquals(1, crlMap.size());
				for (PdfObjectKey crl : crls) {
					assertNotNull(crlMap.get(crl));
				}
			}
			
			PAdESOCSPSource ocspSource = (PAdESOCSPSource) signature.getOCSPSource();
			Map<PdfObjectKey, OCSPResponseBinary> ocspMap = ocspSource.getOcspMap();
			if (match) {
				assertEquals(1, ocspMap.size());
				for (PdfObjectKey ocsp : ocsps) {
					assertNotNull(ocspMap.get(ocsp));
				}
			}
			
			PAdESCertificateSource certificateSource = (PAdESCertificateSource) signature.getCertificateSource();
			Map<PdfObjectKey, CertificateToken> certificateMap = certificateSource.getCertificateMap();
			if (match) {
				for (PdfObjectKey cert : certs) {
					assertNotNull(certificateMap.get(cert));
				}
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
