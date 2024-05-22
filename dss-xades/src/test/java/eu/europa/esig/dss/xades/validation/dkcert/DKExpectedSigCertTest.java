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
package eu.europa.esig.dss.xades.validation.dkcert;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class DKExpectedSigCertTest extends AbstractDKTestCertificate {
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		try {
			SignedDocumentValidator validator = super.getValidator(signedDocument);
			CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
			CommonTrustedCertificateSource certSource = new CommonTrustedCertificateSource();
			certSource.addCertificate(EXPECTED_SIG_CERT);
			certificateVerifier.setTrustedCertSources(certSource);
			certificateVerifier.setAIASource(new DefaultAIASource(getMemoryDataLoader()));
			validator.setCertificateVerifier(certificateVerifier);
			validator.setProcessExecutor(fixedTime());
			return validator;
		} catch (ParseException e) {
			fail(e);
			return null;
		}
	}
	
	@Override
	protected void checkTokens(DiagnosticData diagnosticData) {
		super.checkTokens(diagnosticData);
		for (CertificateWrapper certificateWrapper : diagnosticData.getUsedCertificates()) {
			assertFalse(certificateWrapper.isTrusted());
		}
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void certs() {
		// System.out.println(PREVIOUS_SIG_CERT);
		// System.out.println(EXPECTED_SIG_CERT);

		assertFalse(PREVIOUS_SIG_CERT.isEquivalent(EXPECTED_SIG_CERT));
		assertFalse(PREVIOUS_SIG_CERT.isEquivalent(AIA_CERT));
		assertFalse(EXPECTED_SIG_CERT.isEquivalent(AIA_CERT));
		assertNotEquals(PREVIOUS_SIG_CERT.getPublicKey(), EXPECTED_SIG_CERT.getPublicKey());
		assertNotEquals(PREVIOUS_SIG_CERT.getPublicKey(), AIA_CERT.getPublicKey());
		assertNotEquals(EXPECTED_SIG_CERT.getPublicKey(), AIA_CERT.getPublicKey());
		assertNotEquals(PREVIOUS_SIG_CERT.getEntityKey(), EXPECTED_SIG_CERT.getEntityKey());
		assertNotEquals(PREVIOUS_SIG_CERT.getEntityKey(), AIA_CERT.getEntityKey());
		assertNotEquals(EXPECTED_SIG_CERT.getEntityKey(), AIA_CERT.getEntityKey());
		assertNotEquals(PREVIOUS_SIG_CERT.getDSSId(), EXPECTED_SIG_CERT.getDSSId());
		assertNotEquals(PREVIOUS_SIG_CERT.getDSSId(), AIA_CERT.getDSSId());
		assertNotEquals(EXPECTED_SIG_CERT.getDSSId(), AIA_CERT.getDSSId());
		assertEquals(PREVIOUS_SIG_CERT.getSubject(), EXPECTED_SIG_CERT.getSubject());
	}

}
