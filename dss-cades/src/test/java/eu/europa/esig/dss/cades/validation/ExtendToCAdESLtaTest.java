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
package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;

/**
 * Unit test to fix issue https://esig-dss.atlassian.net/browse/DSS-646
 */
public class ExtendToCAdESLtaTest extends AbstractCAdESTestValidation {

	private static final String SIGNED_DOC_PATH = "src/test/resources/validation/dss-646/CAdES_A_DETACHED.csig";
	private static final String DETACHED_DOC_PATH = "src/test/resources/validation/dss-646/document.pdf";

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(SIGNED_DOC_PATH);
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.asList(new FileDocument(DETACHED_DOC_PATH));
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertFalse(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Test
	public void testExtend() throws Exception {
		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		DSSDocument detachedContent = new FileDocument(DETACHED_DOC_PATH);
		parameters.setDetachedContents(Arrays.asList(detachedContent));
		FileDocument document = new FileDocument(SIGNED_DOC_PATH);
		Exception exception = assertThrows(DSSException.class, () -> service.extendDocument(document, parameters));
		assertEquals("Cryptographic signature verification has failed.", exception.getMessage());
	}

}
