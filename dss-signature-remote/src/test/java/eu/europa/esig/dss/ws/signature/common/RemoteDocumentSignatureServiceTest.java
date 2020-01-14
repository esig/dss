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
package eu.europa.esig.dss.ws.signature.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;

public class RemoteDocumentSignatureServiceTest extends AbstractRemoteSignatureServiceTest {
	
	private RemoteDocumentSignatureServiceImpl signatureService;
	
	@BeforeEach
	public void init() {
		signatureService = new RemoteDocumentSignatureServiceImpl();
		signatureService.setXadesService(getXAdESService());
		signatureService.setPadesService(getPAdESService());
	}

	@Test
	public void testSigningAndExtension() throws Exception {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());
		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocument, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);

		parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

		RemoteDocument extendedDocument = signatureService.extendDocument(signedDocument, parameters);

		assertNotNull(extendedDocument);

		InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
		validate(iMD, null);
	}

	@Test
	public void testSigningAndExtensionDigestDocument() throws Exception {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileToSign), DigestAlgorithm.SHA256,
				fileToSign.getName());

		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocument, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);

		parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		parameters.setDetachedContents(Arrays.asList(toSignDocument));

		RemoteDocument extendedDocument = signatureService.extendDocument(signedDocument, parameters);

		assertNotNull(extendedDocument);

		InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
		validate(iMD, RemoteDocumentConverter.toDSSDocuments(Arrays.asList(toSignDocument)));
	}

	@Test
	public void testSigningAndExtensionDigestDocumentRSASSA_PSS() throws Exception {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		parameters.setMaskGenerationFunction(MaskGenerationFunction.MGF1);

		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileToSign), DigestAlgorithm.SHA256,
				fileToSign.getName());

		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocument, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, MaskGenerationFunction.MGF1, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);

		parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		parameters.setDetachedContents(Arrays.asList(toSignDocument));

		RemoteDocument extendedDocument = signatureService.extendDocument(signedDocument, parameters);

		assertNotNull(extendedDocument);

		InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
		validate(iMD, RemoteDocumentConverter.toDSSDocuments(Arrays.asList(toSignDocument)));
	}
	
	@Test
	public void testTimestamping() throws Exception {
		RemoteTimestampParameters remoteTimestampParameters = new RemoteTimestampParameters();
		remoteTimestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		remoteTimestampParameters.setSignatureForm(SignatureForm.PAdES);
		
		FileDocument fileToTimestamp = new FileDocument(new File("src/test/resources/sample.pdf"));
		RemoteDocument remoteDocument = RemoteDocumentConverter.toRemoteDocument(fileToTimestamp);
		
		RemoteDocument timestampedDocument = signatureService.timestamp(remoteDocument, remoteTimestampParameters);
		
		InMemoryDocument iMD = new InMemoryDocument(timestampedDocument.getBytes());
		DiagnosticData diagnosticData = validate(iMD, Collections.emptyList());
		
		assertEquals(0, diagnosticData.getSignatures().size());
		assertEquals(1, diagnosticData.getTimestampList().size());
	}

}
