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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class PolicySPURITest {

	@Test
	public void test() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-728/CADES-B-DETACHED-withpolicy1586434883385020407.cades");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new MockDataLoader());
		validator.setCertificateVerifier(certificateVerifier);
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(new FileDocument("src/test/resources/validation/dss-728/InfoSelladoTiempo.pdf"));
		validator.setDetachedContents(detachedContents);
		Reports reports = validator.validateDocument();

		validatePolicy(reports);

	}

	@Test
	public void testWithFilePolicy() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/validation/dss-728/CADES-B-DETACHED-withpolicy1586434883385020407.cades");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);

		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<String, DSSDocument>();
		signaturePoliciesByUrl.put("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf",
				new FileDocument(new File("src/test/resources/validation/dss-728/politica_de_firma_anexo_1.pdf")));
		signaturePolicyProvider.setSignaturePoliciesByUrl(signaturePoliciesByUrl);
		validator.setSignaturePolicyProvider(signaturePolicyProvider);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(new FileDocument("src/test/resources/validation/dss-728/InfoSelladoTiempo.pdf"));
		validator.setDetachedContents(detachedContents);
		Reports reports = validator.validateDocument();

		validatePolicy(reports);
	}

	private void validatePolicy(Reports reports) {
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		SignatureWrapper signatureWrapper = signatures.get(0);

		String policyId = diagnosticData.getFirstPolicyId();
		assertEquals("2.16.724.1.3.1.1.2.1.9", policyId);
		assertEquals("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf", signatureWrapper.getPolicyUrl());
		assertFalse(signatureWrapper.isPolicyAsn1Processable());
		assertTrue(signatureWrapper.isPolicyIdentified());
		assertTrue(signatureWrapper.isPolicyStatus());

	}

}
