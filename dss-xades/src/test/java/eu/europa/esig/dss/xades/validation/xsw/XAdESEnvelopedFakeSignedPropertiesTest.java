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
package eu.europa.esig.dss.xades.validation.xsw;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

public class XAdESEnvelopedFakeSignedPropertiesTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloped-fake-signedProperties.xml"));
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		
		CommonTrustedCertificateSource trustedListsCertificateSource = new CommonTrustedCertificateSource();
		
		CertificateToken rootToken = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");
		trustedListsCertificateSource.addCertificate(rootToken);
		
		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();

		certificateVerifier.setTrustedCertSources(trustedListsCertificateSource);
		validator.setCertificateVerifier(certificateVerifier);
		
		return validator;
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isSignatureIntact());
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

}
