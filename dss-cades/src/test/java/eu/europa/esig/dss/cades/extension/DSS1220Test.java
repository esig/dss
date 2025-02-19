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
package eu.europa.esig.dss.cades.extension;


import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS1220Test extends PKIFactoryAccess {

	@Test
	void brokenT() {
		CAdESService service = new CAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);

		DSSDocument toExtendDocument = new InMemoryDocument(DSS1220Test.class.getResourceAsStream("/validation/dss-1220/CAdES-BpT_modified_ts_hash.p7m"));
		assertThrows(AlertException.class, () -> service.extendDocument(toExtendDocument, parameters));
	}

	@Test
	void brokenLTA1() {
		CAdESService service = new CAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);

		DSSDocument toExtendDocument = new InMemoryDocument(DSS1220Test.class.getResourceAsStream("/validation/dss-1220/CAdES-BpLTA_modified_ats_hash_element.p7m"));
		assertThrows(AlertException.class, () -> service.extendDocument(toExtendDocument, parameters));
	}

	@Test
	void brokenLTA2() {
		CAdESService service = new CAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);

		DSSDocument toExtendDocument = new InMemoryDocument(DSS1220Test.class.getResourceAsStream("/validation/dss-1220/CAdES-BpLTA_removed_ocsp.p7m"));
		assertThrows(AlertException.class, () -> service.extendDocument(toExtendDocument, parameters));
	}

	@Test
	void revokedCert() {
		CertificateToken trustAnchor = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");

		CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();

		ListCertificateSource trustedCertSources = completeCertificateVerifier.getTrustedCertSources();
		trustedCertSources.getSources().get(0).addCertificate(trustAnchor);

		CAdESService service = new CAdESService(completeCertificateVerifier);
		service.setTspSource(getGoodTsa());

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);

		DSSDocument toExtendDocument = new InMemoryDocument(DSS1220Test.class.getResourceAsStream("/validation/dss-1220/CAdES-BpB_revoked_signingCertificate.p7m"));
		Exception exception = assertThrows(AlertException.class, () -> service.extendDocument(toExtendDocument, parameters));
		assertTrue(exception.getMessage().contains("Error on signature augmentation"));
		assertTrue(exception.getMessage().contains("is expired at signing time"));
	}

	// See DSS-3507
	@Test
	void brokenTNoSignCert() {
		CAdESService service = new CAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());

		CAdESSignatureParameters parameters = new CAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);

		DSSDocument toExtendDocument = new InMemoryDocument(DSS1220Test.class.getResourceAsStream("/validation/cades-broken-sig-tst.p7m"));
		assertThrows(AlertException.class, () -> service.extendDocument(toExtendDocument, parameters));
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}
}
