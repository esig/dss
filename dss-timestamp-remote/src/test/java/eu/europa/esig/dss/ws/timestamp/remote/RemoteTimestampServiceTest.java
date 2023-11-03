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
package eu.europa.esig.dss.ws.timestamp.remote;

import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.timestamp.dto.TimestampResponseDTO;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.File;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RemoteTimestampServiceTest extends PKIFactoryAccess {
	
	private RemoteTimestampService timestampService;
	
	@BeforeEach
	public void init() {
		timestampService = new RemoteTimestampService();
		timestampService.setTSPSource(getGoodTsa());
	}
	
	@Test
	public void simpleTest() {
		byte[] contentToBeTimestamped = "Hello World!".getBytes();
		byte[] digestValue = DSSUtils.digest(DigestAlgorithm.SHA512, contentToBeTimestamped);
		TimestampResponseDTO timestampResponse = timestampService.getTimestampResponse(DigestAlgorithm.SHA512, digestValue);
		assertNotNull(timestampResponse);
		assertTrue(Utils.isArrayNotEmpty(timestampResponse.getBinaries()));
	}
	
	@Test
	public void signatureWithContentTimestamp() throws Exception {
		DSSDocument documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		
		String canonicalizationAlgo = CanonicalizationMethod.EXCLUSIVE;
		DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA512;

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(digestAlgorithm);
		
		byte[] digest = DSSUtils.digest(digestAlgorithm, XMLCanonicalizer.createInstance(canonicalizationAlgo).canonicalize(DSSUtils.toByteArray(documentToSign)));
		TimestampResponseDTO timeStampResponse = timestampService.getTimestampResponse(digestAlgorithm, digest);
		TimestampToken timestampToken = new TimestampToken(timeStampResponse.getBinaries(), TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);
		timestampToken.setCanonicalizationMethod(canonicalizationAlgo);
		signatureParameters.setContentTimestamps(Collections.singletonList(timestampToken));
		
		XAdESService service = new XAdESService(getCompleteCertificateVerifier());
		
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
				signatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_TIMESTAMPS_ONLY);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertNotNull(timestampList);
		assertEquals(1, timestampList.size());
		
		TimestampWrapper timestamp = timestampList.get(0);
		assertTrue(timestamp.getType().isContentTimestamp());
		assertEquals(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP, timestamp.getType());
		assertArrayEquals(timeStampResponse.getBinaries(), timestamp.getBinaries());
	}
	
	@Test
	public void noTSPSourceDefinedTest() {
		RemoteTimestampService remoteTimestampService = new RemoteTimestampService();
		byte[] contentToBeTimestamped = "Hello World!".getBytes();
		byte[] digestValue = DSSUtils.digest(DigestAlgorithm.SHA512, contentToBeTimestamped);
		Exception exception = assertThrows(NullPointerException.class,
				() -> remoteTimestampService.getTimestampResponse(DigestAlgorithm.SHA512, digestValue));
		assertEquals("TSPSource must be not null!", exception.getMessage());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
