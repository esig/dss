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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.TimestampContainerForm;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.converter.ColorConverter;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureFieldParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureImageParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureImageTextParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RemoteDocumentSignatureServiceTest extends AbstractRemoteSignatureServiceTest {
	
	private RemoteDocumentSignatureServiceImpl signatureService;
	
	@BeforeEach
	public void init() {
		signatureService = new RemoteDocumentSignatureServiceImpl();
		signatureService.setXadesService(getXAdESService());
		signatureService.setCadesService(getCAdESService());
		signatureService.setPadesService(getPAdESService());
		signatureService.setJadesService(getJAdESService());
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
		RemoteDocument digestDocument = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileToSign), DigestAlgorithm.SHA256,
				fileToSign.getName());

		ToBeSignedDTO dataToSign = signatureService.getDataToSign(digestDocument, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(digestDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);

		InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
		validate(iMD, RemoteDocumentConverter.toDSSDocuments(Arrays.asList(digestDocument)));

		RemoteSignatureParameters extensionParameters = new RemoteSignatureParameters();
		extensionParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		extensionParameters.setDetachedContents(Arrays.asList(digestDocument));
		Exception exception = assertThrows(IllegalArgumentException.class,
				() -> signatureService.extendDocument(signedDocument, extensionParameters));
		assertEquals("XAdES-LTA requires complete binaries of signed documents! Extension with a DigestDocument is not possible.", exception.getMessage());
	}

	@Test
	public void testCAdESSigningAndExtensionDigestDocument() throws Exception {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
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
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		parameters.setDetachedContents(Arrays.asList(toSignDocument));

		RemoteDocument extendedDocument = signatureService.extendDocument(signedDocument, parameters);

		assertNotNull(extendedDocument);

		InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
		validate(iMD, RemoteDocumentConverter.toDSSDocuments(Arrays.asList(toSignDocument)));
	}

	@Test
	public void testCAdESSigningAndExtensionDigestDocumentRSASSA_PSS() throws Exception {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
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
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		parameters.setDetachedContents(Arrays.asList(toSignDocument));

		RemoteDocument extendedDocument = signatureService.extendDocument(signedDocument, parameters);

		assertNotNull(extendedDocument);

		InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
		validate(iMD, RemoteDocumentConverter.toDSSDocuments(Arrays.asList(toSignDocument)));
	}
	
	@Test
	public void testPAdESVisible() throws IOException {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		RemoteSignatureImageParameters imageParameters = new RemoteSignatureImageParameters();
		RemoteDocument image = new RemoteDocument();
		image.setName("picture.png");
		image.setBytes(Utils.fromBase64(
				"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"));
		imageParameters.setImage(image);
		imageParameters.setRotation(VisualSignatureRotation.NONE);
		imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.NONE);
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.MIDDLE);
		
		RemoteSignatureFieldParameters fieldParameters = new RemoteSignatureFieldParameters();
		fieldParameters.setPage(1);
		fieldParameters.setOriginX(200.F);
		fieldParameters.setOriginY(100.F);
		fieldParameters.setWidth(130.F);
		fieldParameters.setHeight(50.F);
		imageParameters.setFieldParameters(fieldParameters);

		RemoteSignatureImageTextParameters textParameters = new RemoteSignatureImageTextParameters();
		textParameters.setText("Signature");
		textParameters.setSize(14);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.CENTER);
		textParameters.setTextColor(ColorConverter.toRemoteColor(Color.BLUE));
		textParameters.setBackgroundColor(ColorConverter.toRemoteColor(Color.WHITE));
		imageParameters.setTextParameters(textParameters);
		parameters.setImageParameters(imageParameters);

		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
		RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocument, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);

		InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
		validate(iMD, null);
	}

	@Test
	public void testWithSignatureFieldId() throws Exception {
		RemoteSignatureImageParameters imageParameters = new RemoteSignatureImageParameters();
		RemoteSignatureFieldParameters fieldParameters = new RemoteSignatureFieldParameters();
		imageParameters.setFieldParameters(fieldParameters);
		
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		parameters.setImageParameters(imageParameters);
		fieldParameters.setFieldId("signature-test");

		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample-with-empty-signature-fields.pdf"));
		RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());

		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocument, parameters);
		assertNotNull(dataToSign);
		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
		assertNotNull(signedDocument);

		DSSDocument document = new InMemoryDocument(signedDocument.getBytes());
		DiagnosticData diagnosticData = validate(document, null);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(1, signature.getSignatureFieldNames().size());
		assertEquals("signature-test", signature.getSignatureFieldNames().get(0));

		fieldParameters.setFieldId(null);
		
		dataToSign = signatureService.getDataToSign(signedDocument, parameters);
		assertNotNull(dataToSign);
		signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedTwiceDocument = signatureService.signDocument(signedDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));
		assertNotNull(signedTwiceDocument);

		document = new InMemoryDocument(signedTwiceDocument.getBytes());
		diagnosticData = validate(document, null);
		
		assertEquals(2, diagnosticData.getSignatures().size());
		assertEquals("signature-test", diagnosticData.getSignatures().get(0).getSignatureFieldNames().get(0));
		assertNotEquals("signature-test", diagnosticData.getSignatures().get(1).getSignatureFieldNames().get(0));
		assertNotEquals("signature-test2", diagnosticData.getSignatures().get(1).getSignatureFieldNames().get(0));

		fieldParameters.setFieldId("signature-test");

		Exception exception = assertThrows(IllegalArgumentException.class,() -> signatureService.getDataToSign(signedTwiceDocument, parameters));
		assertEquals("The signature field 'signature-test' can not be signed since its already signed.", exception.getMessage());
	}

	@Test
	public void testSignJAdES() throws Exception {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		parameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);

		DSSDocument fileToSign = new InMemoryDocument("HelloWorld".getBytes());
		RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());
		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocument, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);
		InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
		validate(iMD, null);
	}

	@Test
	public void testSignDetachedJAdES() throws Exception {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		parameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);

		DSSDocument fileToSign = new InMemoryDocument("HelloWorld".getBytes(), "helloWorld");
		RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());
		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocument, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);
		InMemoryDocument iMD = new InMemoryDocument(signedDocument.getBytes());
		validate(iMD, Arrays.asList(fileToSign));
	}

	@Test
	public void testTimestamping() throws Exception {
		RemoteTimestampParameters remoteTimestampParameters = new RemoteTimestampParameters();
		remoteTimestampParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		remoteTimestampParameters.setTimestampContainerForm(TimestampContainerForm.PDF);
		
		FileDocument fileToTimestamp = new FileDocument(new File("src/test/resources/sample.pdf"));
		RemoteDocument remoteDocument = RemoteDocumentConverter.toRemoteDocument(fileToTimestamp);
		
		RemoteDocument timestampedDocument = signatureService.timestamp(remoteDocument, remoteTimestampParameters);
		
		InMemoryDocument iMD = new InMemoryDocument(timestampedDocument.getBytes());
		DiagnosticData diagnosticData = validate(iMD, Collections.emptyList());
		
		assertEquals(0, diagnosticData.getSignatures().size());
		assertEquals(1, diagnosticData.getTimestampList().size());
	}

	@Test
	public void testCounterSignature() throws Exception {
		DSSDocument fileToCounterSign = new FileDocument(new File("src/test/resources/xades-signed.xml"));
		RemoteDocument signatureDocument = new RemoteDocument(Utils.toByteArray(fileToCounterSign.openStream()),
				fileToCounterSign.getName());

		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
		parameters.setSignatureIdToCounterSign("id-910825ec07149183c174c83fce12ac93");

		ToBeSignedDTO dataToBeCounterSigned = signatureService.getDataToBeCounterSigned(signatureDocument, parameters);
		assertNotNull(dataToBeCounterSigned);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToBeCounterSigned),
				DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument counterSignedDocument = signatureService.counterSignSignature(signatureDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(counterSignedDocument);

		DSSDocument dssDocument = new InMemoryDocument(counterSignedDocument.getBytes());

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getAllSignatures().size());
		assertEquals(1, diagnosticData.getAllCounterSignatures().size());

		String counterSignatureId = diagnosticData.getAllCounterSignatures().iterator().next().getId();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(counterSignatureId));
	}

	@Test
	public void testSignAndCounterSignDetached() throws Exception {
		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileToSign),
				DigestAlgorithm.SHA256, fileToSign.getName());

		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocument, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256,
				getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		DiagnosticData diagnosticData = validate(new InMemoryDocument(signedDocument.getBytes()),
				Arrays.asList(fileToSign));
		assertEquals(1, diagnosticData.getAllSignatures().size());
		assertEquals(0, diagnosticData.getAllCounterSignatures().size());

		parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
		parameters.setSignatureIdToCounterSign(diagnosticData.getFirstSignatureId());
		parameters.setDetachedContents(Arrays.asList(toSignDocument));

		ToBeSignedDTO dataToBeCounterSigned = signatureService.getDataToBeCounterSigned(signedDocument, parameters);
		assertNotNull(dataToBeCounterSigned);

		signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToBeCounterSigned), DigestAlgorithm.SHA512,
				getPrivateKeyEntry());
		RemoteDocument counterSignedDocument = signatureService.counterSignSignature(signedDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(counterSignedDocument);

		diagnosticData = validate(new InMemoryDocument(counterSignedDocument.getBytes()), Arrays.asList(fileToSign));
		assertEquals(1, diagnosticData.getAllSignatures().size());
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getAllSignatures().iterator().next().getId()));
		assertEquals(1, diagnosticData.getAllCounterSignatures().size());
		assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getAllCounterSignatures().iterator().next().getId()));
	}

	@Test
	public void testPAdESCounterSign() throws Exception {
		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.pdf"));
		RemoteDocument toCounterSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()),
				fileToSign.getName());

		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		Exception exception = assertThrows(UnsupportedOperationException.class,
				() -> signatureService.getDataToBeCounterSigned(toCounterSignDocument, parameters));
		assertEquals("Unsupported signature form for counter signature : PAdES", exception.getMessage());
	}

}
