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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

public class OpenDocumentLevelBWithExternalDataTest extends AbstractOpenDocumentTestSignature {

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
	public void init() {
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

	@Override
	@ParameterizedTest(name = "Validation {index} : {0}")
	@MethodSource("data")
	public void test(DSSDocument fileToTest) {
		super.test(fileToTest);
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

	protected DSSDocument removeExternalDataFilesFromContainer(DSSDocument archiveDocument) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				ZipOutputStream zos = new ZipOutputStream(baos)) {
			copyArchiveContentWithoutExternalData(archiveDocument, zos);

			zos.finish();

			return new InMemoryDocument(baos.toByteArray(), null, archiveDocument.getMimeType());
		} catch (IOException e) {
			throw new DSSException("Unable to extend the ASiC container", e);
		}
	}

	private void copyArchiveContentWithoutExternalData(DSSDocument archiveDocument, ZipOutputStream zos)
			throws IOException {
		long containerSize = DSSUtils.getFileByteSize(archiveDocument);
		try (InputStream is = archiveDocument.openStream(); ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry entry;
			while ((entry = ASiCUtils.getNextValidEntry(zis)) != null) {
				final String name = entry.getName();
				final ZipEntry newEntry = new ZipEntry(name);
				if (!name.equals("external-data/test.txt")) {
					zos.putNextEntry(newEntry);
					ASiCUtils.secureCopy(zis, zos, containerSize);
				}
			}
		}
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
