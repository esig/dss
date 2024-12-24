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
package eu.europa.esig.dss.ws.signature.common;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampContainerForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RemoteMultipleDocumentsSignatureServiceTest extends AbstractRemoteSignatureServiceTest {
	
	private RemoteMultipleDocumentsSignatureServiceImpl signatureService;
	
	@BeforeEach
	void init() {
		signatureService = new RemoteMultipleDocumentsSignatureServiceImpl();
		signatureService.setXadesService(getXAdESService());
		signatureService.setAsicWithXAdESService(getASiCXAdESService());
		signatureService.setAsicWithCAdESService(getASiCCAdESService());
	}

	@Test
	void testSigningAndExtensionMultiDocuments() throws Exception {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setAsicContainerType(ASiCContainerType.ASiC_E);
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(fileToSign), fileToSign.getName());
		RemoteDocument toSignDoc2 = new RemoteDocument("Hello world!".getBytes(StandardCharsets.UTF_8), "test.bin");
		List<RemoteDocument> toSignDocuments = new ArrayList<>();
		toSignDocuments.add(toSignDocument);
		toSignDocuments.add(toSignDoc2);
		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocuments, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocuments, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);

		parameters = new RemoteSignatureParameters();
		parameters.setAsicContainerType(ASiCContainerType.ASiC_E);
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

		RemoteDocument extendedDocument = signatureService.extendDocument(signedDocument, parameters);

		assertNotNull(extendedDocument);

		InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
		// iMD.save("target/test.asice");
		
		validate(iMD, null);
	}
	
	@Test
	void multipleDocumentTimestampingTest() throws Exception {
		RemoteTimestampParameters timestampParameters = new RemoteTimestampParameters();
		timestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		timestampParameters.setTimestampContainerForm(TimestampContainerForm.ASiC_E);
		
		List<DSSDocument> filesToTimestamp = Arrays.asList(new DSSDocument[] {
				new FileDocument(new File("src/test/resources/sample.xml")),
				new FileDocument(new File("src/test/resources/sample.pdf"))
				});
		
		List<RemoteDocument> remoteDocuments = RemoteDocumentConverter.toRemoteDocuments(filesToTimestamp);
		RemoteDocument timestampedDocument = signatureService.timestamp(remoteDocuments, timestampParameters);
		
		InMemoryDocument iMD = new InMemoryDocument(timestampedDocument.getBytes());
		DiagnosticData diagnosticData = validate(iMD, filesToTimestamp);
		
		assertEquals(0, diagnosticData.getSignatures().size());
		assertEquals(1, diagnosticData.getTimestampList().size());
		assertEquals(0, diagnosticData.getOriginalSignerDocuments().size());
		assertEquals(3, diagnosticData.getAllSignerDocuments().size()); // plus manifest file
	}

	@Test
	void testDetachedSigningAndExtension() {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		InMemoryDocument fileToSign2 = new InMemoryDocument("Hello world!".getBytes(StandardCharsets.UTF_8), "test.bin");
		RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(fileToSign), fileToSign.getName());
		RemoteDocument toSignDoc2 = new RemoteDocument(DSSUtils.toByteArray(fileToSign2), fileToSign2.getName());

		List<RemoteDocument> toSignDocuments = new ArrayList<>();
		toSignDocuments.add(toSignDocument);
		toSignDocuments.add(toSignDoc2);
		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocuments, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocuments, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);

		parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		parameters.setDetachedContents(toSignDocuments);

		RemoteDocument extendedDocument = signatureService.extendDocument(signedDocument, parameters);

		assertNotNull(extendedDocument);

		InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
		validate(iMD, Arrays.asList(fileToSign, fileToSign2));
	}

}
