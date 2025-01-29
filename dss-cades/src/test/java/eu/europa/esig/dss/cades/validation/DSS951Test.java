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
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSS951Test extends AbstractCAdESTestValidation {
	
	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(DSS951Test.class.getResourceAsStream("/validation/dss-951/NexU-CAdES-B-B-Detached-Sha512.p7m"));
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
		certificateVerifier.addTrustedCertSources(trustedCertificateSource);
		validator.setCertificateVerifier(certificateVerifier);
		return validator;
	}

	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getOriginalSignerDocuments()));
	}
	
	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		assertNull(signersDocument);
	}

}
