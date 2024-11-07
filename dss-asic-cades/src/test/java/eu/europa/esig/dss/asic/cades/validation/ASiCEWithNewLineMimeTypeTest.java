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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithNewLineMimeTypeTest extends AbstractASiCWithCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/asice-cades-new-line-mimetype");
	}
	
	@Override
	protected void checkContainerInfo(DiagnosticData diagnosticData) {
		super.checkContainerInfo(diagnosticData);

		XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
		assertNotNull(containerInfo);
		assertEquals(ASiCContainerType.ASiC_E, containerInfo.getContainerType());
		assertEquals("mimetype=application/vnd.etsi.asic-e+zip\n", containerInfo.getZipComment());
		assertTrue(containerInfo.isMimeTypeFilePresent());
		assertEquals("application/vnd.etsi.asic-e+zip\r\n", containerInfo.getMimeTypeContent());
	}

	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<DSSDocument> retrievedDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		assertEquals(3, retrievedDocuments.size());
	}

}
