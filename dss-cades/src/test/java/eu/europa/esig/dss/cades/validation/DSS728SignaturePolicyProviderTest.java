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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanCertificateTokenWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS728SignaturePolicyProviderTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss-728/CADES-B-DETACHED-withpolicy1586434883385020407.cades");
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<>();
		signaturePoliciesByUrl.put("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf",
				new FileDocument(new File("src/test/resources/validation/dss-728/politica_de_firma_anexo_1.pdf")));
		signaturePolicyProvider.setSignaturePoliciesByUrl(signaturePoliciesByUrl);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		return validator;
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.asList(new FileDocument("src/test/resources/validation/dss-728/InfoSelladoTiempo.pdf"));
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		// root cert, because there is no CA cert
		List<OrphanCertificateTokenWrapper> allOrphanCertificateObjects = diagnosticData.getAllOrphanCertificateObjects();
		assertEquals(1, allOrphanCertificateObjects.size());
		OrphanCertificateTokenWrapper orphan = allOrphanCertificateObjects.iterator().next();
		assertNotNull(orphan);
		assertNotNull(orphan.getCertificateDN());
		assertNotNull(orphan.getCertificateIssuerDN());
		assertNotNull(orphan.getSerialNumber());
		assertNotNull(orphan.getNotAfter());
		assertNotNull(orphan.getNotBefore());
		assertFalse(orphan.isTrusted());
		assertTrue(orphan.isSelfSigned());
		assertEquals(0, diagnosticData.getAllOrphanRevocationObjects().size());
	}

}
