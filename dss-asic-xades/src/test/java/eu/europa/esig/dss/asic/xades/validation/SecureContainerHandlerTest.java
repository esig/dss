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

import eu.europa.esig.dss.asic.common.SecureContainerHandler;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SecureContainerHandlerTest extends PKIFactoryAccess {

	private static DSSDocument smallerDocument;
	private static DSSDocument biggerDocument;

	@BeforeAll
	public static void init() {
		smallerDocument = new FileDocument("src/test/resources/validation/dss-2245-2400.asice");
		biggerDocument = new FileDocument("src/test/resources/validation/dss-2245-2500.asice");
	}

	@Test
	public void testDefault() {
		ZipUtils.getInstance().setZipContainerHandler(new SecureContainerHandler());

		DocumentValidator validator = getValidator(smallerDocument);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		validator = getValidator(biggerDocument);
		reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Test
	public void testSmallerRatio() {
		SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
		secureContainerHandler.setMaxCompressionRatio(50);
		ZipUtils.getInstance().setZipContainerHandler(secureContainerHandler);

		DocumentValidator validator = getValidator(smallerDocument);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		Exception exception = assertThrows(IllegalInputException.class, () -> getValidator(biggerDocument));
		assertEquals("Zip Bomb detected in the ZIP container. Validation is interrupted.", exception.getMessage());
	}

	@Test
	public void testBiggerThreshold() {
		SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
		secureContainerHandler.setMaxCompressionRatio(50);
		ZipUtils.getInstance().setZipContainerHandler(secureContainerHandler);

		Exception exception = assertThrows(IllegalInputException.class, () -> getValidator(biggerDocument));
		assertEquals("Zip Bomb detected in the ZIP container. Validation is interrupted.", exception.getMessage());

		secureContainerHandler.setThreshold(100000000);

		DocumentValidator validator = getValidator(biggerDocument);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Test
	public void testDifferentDocumentsAmount() {
		SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
		secureContainerHandler.setMaxAllowedFilesAmount(1);
		ZipUtils.getInstance().setZipContainerHandler(secureContainerHandler);

		Exception exception = assertThrows(IllegalInputException.class, () -> getValidator(smallerDocument));
		assertEquals("Too many files detected. Cannot extract ASiC content from the file.", exception.getMessage());
	}

	private DocumentValidator getValidator(DSSDocument documentToValidate) {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator(documentToValidate);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		return validator;
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
