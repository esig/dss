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

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.OnlineAIASource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class DKPreviousSigCertTest extends AbstractDKTestCertificate {
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		try {
			SignedDocumentValidator validator = super.getValidator(signedDocument);
			CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
			CommonTrustedCertificateSource certSource = new CommonTrustedCertificateSource();
			certSource.addCertificate(PREVIOUS_SIG_CERT);
			certificateVerifier.setTrustedCertSources(certSource);
			certificateVerifier.setAIASource(new OnlineAIASource(getMemoryDataLoader()));
			validator.setCertificateVerifier(certificateVerifier);
			validator.setProcessExecutor(fixedTime());
			return validator;
		} catch (ParseException e) {
			fail(e);
			return null;
		}
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

}
