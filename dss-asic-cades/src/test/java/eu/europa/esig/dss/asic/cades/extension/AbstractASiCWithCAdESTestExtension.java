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
package eu.europa.esig.dss.asic.cades.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.UUID;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.test.extension.AbstractTestExtension;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public abstract class AbstractASiCWithCAdESTestExtension extends AbstractTestExtension<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> {

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
		File originalDoc = new File("target/original-" + UUID.randomUUID().toString() + ".bin");
		try (FileOutputStream fos = new FileOutputStream(originalDoc)) {
			fos.write("Hello world!".getBytes());
		} catch (IOException e) {
			throw new DSSException("Unable to create the original document", e);
		}
		return new FileDocument(originalDoc);
	}

	@Override
	protected DSSDocument getSignedDocument(DSSDocument doc) {
		// Sign
		ASiCWithCAdESSignatureParameters signatureParameters = getSignatureParameters();
		ASiCWithCAdESService service = getSignatureServiceToSign();

		ToBeSigned dataToSign = service.getDataToSign(doc, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				getPrivateKeyEntry());
		return service.signDocument(doc, signatureParameters, signatureValue);
	}

	@Override
	protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
		ASiCWithCAdESSignatureParameters signatureParameters = new ASiCWithCAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(getOriginalSignatureLevel());
		signatureParameters.aSiC().setContainerType(getContainerType());
		return signatureParameters;
	}

	@Override
	protected ASiCWithCAdESSignatureParameters getExtensionParameters() {
		ASiCWithCAdESSignatureParameters extensionParameters = new ASiCWithCAdESSignatureParameters();
		extensionParameters.setSignatureLevel(getFinalSignatureLevel());
		extensionParameters.aSiC().setContainerType(getFinalContainerType());
		return extensionParameters;
	}

	protected abstract ASiCContainerType getContainerType();

	protected ASiCContainerType getFinalContainerType() {
		return getContainerType();
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		assertNotNull(containerInfo);

		assertEquals(getContainerType(), containerInfo.getContainerType());
	}

	@Override
	protected ASiCWithCAdESService getSignatureServiceToSign() {
		ASiCWithCAdESService service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtSignatureTime());
		return service;
	}

	@Override
	protected ASiCWithCAdESService getSignatureServiceToExtend() {
		ASiCWithCAdESService service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getUsedTSPSourceAtExtensionTime());
		return service;
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		assertNotNull(diagnosticData.getContainerInfo());
		assertNotNull(diagnosticData.getContainerType());
		assertNotNull(diagnosticData.getMimetypeFileContent());
		assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
	}
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertNotNull(signatureWrapper.getSignatureValue());
		}
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
				assertTrue(Arrays.equals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue()));
			}
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
