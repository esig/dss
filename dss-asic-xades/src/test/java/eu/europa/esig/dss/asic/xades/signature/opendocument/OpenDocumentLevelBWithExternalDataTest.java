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

import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

class OpenDocumentLevelBWithExternalDataTest extends AbstractOpenDocumentTestSignature {

	private DSSDocument fileToTest;
	private DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> service;
	private ASiCWithXAdESSignatureParameters signatureParameters;
	
	private static Stream<Arguments> data() {
		File file = new File("src/test/resources/signable/open-document-external-data.odt");
		List<Arguments> args = new ArrayList<>();
		args.add(Arguments.of(new FileDocument(file)));
		return args.stream();
	}
	
	@BeforeEach
	void init() {
		fileToTest = new FileDocument(new File("src/test/resources/signable/open-document-external-data.odt"));

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
	void test(DSSDocument fileToTest) {
		this.fileToTest = fileToTest;

		super.signAndVerify();
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		// Both validations must be valid, even after deleting files from external-data
		// OpenDocument Part 1 CH 3.16
		DSSDocument signedDocument = new InMemoryDocument(byteArray);

		signedDocument = removeExternalDataFilesFromContainer(signedDocument);

		SignedDocumentValidator validator = getValidator(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		verifyDiagnosticData(reports.getDiagnosticData());
	}

	private DSSDocument removeExternalDataFilesFromContainer(DSSDocument archiveDocument) {
		List<DSSDocument> containerContent = ZipUtils.getInstance().extractContainerContent(archiveDocument);
		containerContent = getArchiveContentWithoutExternalData(containerContent);
		return ZipUtils.getInstance().createZipArchive(containerContent, null, null);
	}

	private List<DSSDocument> getArchiveContentWithoutExternalData(List<DSSDocument> containerContent) {
		List<DSSDocument> result = new ArrayList<>();
		for (DSSDocument document : containerContent) {
			if (!"external-data/test.txt".equals(document.getName())) {
				result.add(document);
			}
		}
		return result;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return fileToTest;
	}

	@Override
	protected DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
