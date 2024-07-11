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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.asic.common.SecureContainerHandlerBuilder;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("slow")
class ZipBombingTest extends AbstractASiCWithXAdESTestValidation {
	
	private static DSSDocument document;
	
	private static Stream<Arguments> data() {
		List<DSSDocument> docs = new ArrayList<>();
		docs.add(new FileDocument("src/test/resources/validation/zip-bomb.asice"));
		docs.add(new FileDocument("src/test/resources/validation/zip-bomb-package-zip.asics"));
		
		List<Arguments> args = new ArrayList<>();
		for (DSSDocument document : docs) {
			args.add(Arguments.of(document));
		}
		return args.stream();
	}
	
	@ParameterizedTest(name = "Validation {index} : {0}")
	@MethodSource("data")
	void init(DSSDocument fileToTest) {
		document = fileToTest;
		super.validate();
	}

	@AfterEach
	void reset() {
		ZipUtils.getInstance().setZipContainerHandlerBuilder(new SecureContainerHandlerBuilder());
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return document;
	}
	
	@Override
	public void validate() {
		// do nothing
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		// do nothing
	}

	@Test
	void zipBombingOneLevelAsice() {
		FileDocument doc = new FileDocument("src/test/resources/validation/one-level-zip-bombing.asice");
		Exception exception = assertThrows(IllegalInputException.class, () -> SignedDocumentValidator.fromDocument(doc));
		assertEquals("Zip Bomb detected in the ZIP container. Validation is interrupted.", exception.getMessage());
	}

	@Test
	void zipBombingOneLevelAsice2() {
		FileDocument doc = new FileDocument("src/test/resources/validation/one-level-zip-bombing.asice");

		// decreased value to pass the test on low memory configuration (less than -Xmx3072m)
		SecureContainerHandlerBuilder secureContainerHandler = new SecureContainerHandlerBuilder()
				.setMaxCompressionRatio(20);
		ZipUtils.getInstance().setZipContainerHandlerBuilder(secureContainerHandler);

		Exception exception = assertThrows(IllegalInputException.class, () -> new ASiCContainerWithXAdESAnalyzer(doc));
		assertEquals("Zip Bomb detected in the ZIP container. Validation is interrupted.", exception.getMessage());
	}

	@Test
	void zipBombingOneLevelAsics() {
		FileDocument doc = new FileDocument("src/test/resources/validation/zip-bomb-package-zip-1gb.asics");
		Exception exception = assertThrows(IllegalInputException.class, () -> SignedDocumentValidator.fromDocument(doc));
		assertEquals("Zip Bomb detected in the ZIP container. Validation is interrupted.", exception.getMessage());
	}

	@Test
	void zipBombingOneLevelAsics2() {
		FileDocument doc = new FileDocument("src/test/resources/validation/zip-bomb-package-zip-1gb.asics");
		Exception exception = assertThrows(IllegalInputException.class, () -> new ASiCContainerWithXAdESAnalyzer(doc));
		assertEquals("Zip Bomb detected in the ZIP container. Validation is interrupted.", exception.getMessage());
	}

	@Test
	void zipBombingTooManyFilesAsice() {
		FileDocument doc = new FileDocument("src/test/resources/validation/container-too-many-files.asice");
		Exception exception = assertThrows(IllegalInputException.class, () -> SignedDocumentValidator.fromDocument(doc));
		assertEquals("Too many files detected. Cannot extract ASiC content from the file.", exception.getMessage());
	}

	@Test
	void zipBombingTooManyFilesAsics() {
		FileDocument doc = new FileDocument("src/test/resources/validation/container-too-many-files.asics");
		Exception exception = assertThrows(IllegalInputException.class, () -> SignedDocumentValidator.fromDocument(doc));
		assertEquals("Too many files detected. Cannot extract ASiC content from the file.", exception.getMessage());
	}

}
