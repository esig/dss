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
package eu.europa.esig.dss.asic.xades.signature.opendocument;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

public class OpenDocumentLevelBMultipleSignaturesTest extends PKIFactoryAccess {

	private DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> service;
	private ASiCWithXAdESSignatureParameters signatureParameters;

	public static Stream<Arguments> data() {
		File folder = new File("src/test/resources/opendocument");
		Collection<File> listFiles = Utils.listFiles(folder, new String[] { "odt", "ods", "odp", "odg" }, true);
		Collection<Arguments> dataToRun = new ArrayList<>();
		for (File file : listFiles) {
			dataToRun.add(Arguments.of(file));
		}
		return dataToRun.stream();
	}

	@BeforeEach
	public void init() throws Exception {
		signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}

	@ParameterizedTest(name = "Validation {index} : {0}")
	@MethodSource("data")
	public void test(File fileToTest) throws Exception {
		doubleSignature(new FileDocument(fileToTest));
	}

	public void doubleSignature(DSSDocument originalDocument) throws IOException {

		DSSDocument signedDocument = getSignedDocument(originalDocument);
		DSSDocument resignedDocument = getSignedDocument(signedDocument);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(resignedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String sigId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(sigId));
			assertNotEquals(Indication.FAILED, reports.getSimpleReport().getIndication(sigId));
		}

		AbstractASiCContainerExtractor extractor = new ASiCWithXAdESContainerExtractor(resignedDocument);
		ASiCContent result = extractor.extract();

		assertEquals(0, result.getUnsupportedDocuments().size());

		List<DSSDocument> signatureDocuments = result.getSignatureDocuments();
		assertEquals(1, signatureDocuments.size());
		String signatureFilename = signatureDocuments.get(0).getName();
		assertEquals("META-INF/documentsignatures.xml", signatureFilename);

		List<DSSDocument> manifestDocuments = result.getManifestDocuments();
		assertEquals(1, manifestDocuments.size());
		assertEquals("META-INF/manifest.xml", manifestDocuments.get(0).getName());

		List<DSSDocument> signedDocuments = result.getSignedDocuments();
		assertTrue(signedDocuments.size() > 4);

		DSSDocument mimeTypeDocument = result.getMimeTypeDocument();

		byte[] mimeTypeContent = DSSUtils.toByteArray(mimeTypeDocument);
		try {
			assertEquals(originalDocument.getMimeType().getMimeTypeString(), new String(mimeTypeContent, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			fail(e.getMessage());
		}

	}

	private DSSDocument getSignedDocument(DSSDocument originalDocument) {
		DSSDocument documentToSign = originalDocument;

		ASiCWithXAdESSignatureParameters signatureParameters = new ASiCWithXAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

		ASiCWithXAdESService service = new ASiCWithXAdESService(getCompleteCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

		return signedDocument;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
