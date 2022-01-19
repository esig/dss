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
package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.extension.AbstractTestExtension;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SADSSType;
import eu.europa.esig.validationreport.jaxb.SAFilterType;
import eu.europa.esig.validationreport.jaxb.SASubFilterType;
import eu.europa.esig.validationreport.jaxb.SAVRIType;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public abstract class AbstractPAdESTestExtension extends AbstractTestExtension<PAdESSignatureParameters, PAdESTimestampParameters> {

	@Override
	protected TSPSource getUsedTSPSourceAtSignatureTime() {
		return getGoodTsa();
	}

	@Override
	protected TSPSource getUsedTSPSourceAtExtensionTime() {
		return getAlternateGoodTsa();
	}

	@Override
	protected FileDocument getOriginalDocument() {
		File originalDoc = new File("target/original-" + UUID.randomUUID().toString() + ".pdf");
		try (FileOutputStream fos = new FileOutputStream(originalDoc); InputStream is = AbstractPAdESTestExtension.class.getResourceAsStream("/sample.pdf")) {
			Utils.copy(is, fos);
		} catch (IOException e) {
			throw new DSSException("Unable to create the original document", e);
		}
		return new FileDocument(originalDoc);
	}

	@Override
	protected DSSDocument getSignedDocument(DSSDocument doc) {
		// Sign
		PAdESSignatureParameters signatureParameters = getSignatureParameters();
		PAdESService service = getSignatureServiceToSign();

		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}

	@Override
	protected PAdESService getSignatureServiceToSign() {
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtSignatureTime());
		return service;
	}

	@Override
	protected PAdESService getSignatureServiceToExtend() {
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtExtensionTime());
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
		return signatureParameters;
	}

	@Override
	protected PAdESSignatureParameters getExtensionParameters() {
		PAdESSignatureParameters extensionParameters = new PAdESSignatureParameters();
		extensionParameters.setSignatureLevel(getFinalSignatureLevel());
		return extensionParameters;
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		checkTimestamps(diagnosticData);
	}
	
	@Override
	protected void checkValidationContext(SignedDocumentValidator validator) {
		super.checkValidationContext(validator);
		
		PDFDocumentValidator pdfValidator = (PDFDocumentValidator) validator;
		List<PdfDssDict> dssDictionaries = pdfValidator.getDssDictionaries();
		if (Utils.isCollectionNotEmpty(dssDictionaries) && dssDictionaries.size() > 1) {
			Map<Long, CertificateToken> previousCertificateMap = null;
			Map<Long, CRLBinary> previousCrlMap = null;
			Map<Long, OCSPResponseBinary> previousOcspMap = null;
			
			for (PdfDssDict dssDict : dssDictionaries) {
				if (previousCertificateMap != null) {
					Map<Long, CertificateToken> currentMap = dssDict.getCERTs();
					assertFalse(currentMap.size() < previousCertificateMap.size());
					for (Long key : previousCertificateMap.keySet()) {
						assertEquals(previousCertificateMap.get(key), currentMap.get(key));
					}
				}
				previousCertificateMap = dssDict.getCERTs();
				
				if (previousCrlMap != null) {
					Map<Long, CRLBinary> currentMap = dssDict.getCRLs();
					assertFalse(currentMap.size() < previousCrlMap.size());
					for (Long key : previousCrlMap.keySet()) {
						assertEquals(previousCrlMap.get(key), currentMap.get(key));
					}
				}
				previousCrlMap = dssDict.getCRLs();
				
				if (previousOcspMap != null) {
					Map<Long, OCSPResponseBinary> currentMap = dssDict.getOCSPs();
					assertFalse(currentMap.size() < previousOcspMap.size());
					for (Long key : previousOcspMap.keySet()) {
						assertEquals(previousOcspMap.get(key), currentMap.get(key));
					}
				}
				previousOcspMap = dssDict.getOCSPs();
			}
		}
	}

	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature.getSignatureValue());
	}
	
	@Override
	protected void validateETSIDSSType(SADSSType dss) {
		if (SignatureLevel.PAdES_BASELINE_LT.equals(getFinalSignatureLevel()) || SignatureLevel.PAdES_BASELINE_LTA.equals(getFinalSignatureLevel())) {
			assertNotNull(dss);
		}
	}
	
	@Override
	protected void validateETSIVRIType(SAVRIType vri) {
		if (SignatureLevel.PAdES_BASELINE_LT.equals(getFinalSignatureLevel()) || SignatureLevel.PAdES_BASELINE_LTA.equals(getFinalSignatureLevel())) {
			assertNotNull(vri);
		}
	}
	
	@Override
	protected void validateETSIFilter(SAFilterType filterType) {
		assertNotNull(filterType);
	}
	
	@Override
	protected void validateETSISubFilter(SASubFilterType subFilterType) {
		assertNotNull(subFilterType);
	}

	@Override
	protected void checkReportsSignatureIdentifier(Reports reports) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		
		if (Utils.isCollectionNotEmpty(diagnosticData.getSignatures())) {
			for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
				SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());
				
				SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
				assertNotNull(signatureIdentifier);
				
				assertNotNull(signatureIdentifier.getSignatureValue());
				assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
