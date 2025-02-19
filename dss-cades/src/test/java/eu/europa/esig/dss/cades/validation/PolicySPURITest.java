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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicySPURITest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(PolicySPURITest.class.getResourceAsStream("/validation/dss-728/CADES-B-DETACHED-withpolicy1586434883385020407.cades"));
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);

		SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
		signaturePolicyProvider.setDataLoader(new MockDataLoader());
		validator.setSignaturePolicyProvider(signaturePolicyProvider);

		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
		CommonCertificateSource certificateSource = new CommonCertificateSource();
		certificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
		certificateVerifier.addAdjunctCertSources(certificateSource);
		validator.setCertificateVerifier(certificateVerifier);

		return validator;
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Collections.singletonList(new InMemoryDocument(PolicySPURITest.class.getResourceAsStream("/validation/dss-728/InfoSelladoTiempo.pdf")));
	}
	
	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);

		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		SignatureWrapper signatureWrapper = signatures.get(0);

		String policyId = diagnosticData.getFirstPolicyId();
		assertEquals("2.16.724.1.3.1.1.2.1.9", policyId);
		assertEquals("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf", signatureWrapper.getPolicyUrl());
		assertFalse(signatureWrapper.isPolicyAsn1Processable());
		assertTrue(signatureWrapper.isPolicyIdentified());
		assertTrue(signatureWrapper.isPolicyDigestValid());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	private static class MockDataLoader extends CommonsDataLoader {

		private static final long serialVersionUID = -8743201861357700742L;
		
		public MockDataLoader() {
			// empty
		}

		@Override
		public byte[] get(final String urlString) {
			if (urlString.equals("https://sede.060.gob.es/politica_de_firma_anexo_1.pdf")) {
				DSSDocument document = new InMemoryDocument(PolicySPURITest.class.getResourceAsStream("/validation/dss-728/politica_de_firma_anexo_1.pdf"));
				try {
					return Utils.toByteArray(document.openStream());
				} catch (IOException e) {
					throw new DSSException(e);
				}
			} else {
				return super.get(urlString);
			}
		}
	}

}
