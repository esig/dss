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
package eu.europa.esig.dss.cades.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * Unit test to fix issue https://esig-dss.atlassian.net/browse/DSS-646
 */
public class ExtendToCAdESLtaTest extends PKIFactoryAccess {

	private static final String SIGNED_DOC_PATH = "src/test/resources/validation/dss-646/CAdES_A_DETACHED.csig";
	private static final String DETACHED_DOC_PATH = "src/test/resources/validation/dss-646/document.pdf";

	@Test
	public void testValidation() {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(SIGNED_DOC_PATH));
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		List<DSSDocument> detachedContents = new ArrayList<>();
		detachedContents.add(new FileDocument(DETACHED_DOC_PATH));
		validator.setDetachedContents(detachedContents);
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		// The ordering of attributes inside the SET is wrong. The attributes must be ordering by their tags and length
		// Since all the attributes have the same tag, the length decide the order, and the messageDigest should be
		// before the signingTime
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		List<RelatedRevocationWrapper> relatedRevocations = signature.foundRevocations().getRelatedRevocationData();
		assertTrue(Utils.isCollectionNotEmpty(relatedRevocations));
		for (RevocationWrapper revocation : relatedRevocations) {
			assertNotNull(revocation);
			assertNotNull(revocation.getId());
		}
		assertTrue(Utils.isCollectionEmpty(signature.foundRevocations().getOrphanRevocationData()));
		
	}

	@Test
	public void testExtend() throws Exception {
		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		DSSDocument detachedContent = new FileDocument(DETACHED_DOC_PATH);
		parameters.setDetachedContents(Arrays.asList(detachedContent));
		Exception exception = assertThrows(DSSException.class, () -> service.extendDocument(new FileDocument(SIGNED_DOC_PATH), parameters));
		assertEquals("Cryptographic signature verification has failed.", exception.getMessage());
		//DSSDocument extendDocument = service.extendDocument(new FileDocument(SIGNED_DOC_PATH), parameters);
		//assertNotNull(extendDocument);

	}

	@Override
	protected String getSigningAlias() {
		// not for signing
		return null;
	}

}
