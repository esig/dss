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

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESEnvelopedFakeContentSameIdTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/xsw/XSW-enveloped-fake-content-two-same-id.xml"));
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
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		assertTrue(Utils.isCollectionEmpty(diagnosticData.getOriginalSignerDocuments()));
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);

		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.FORMAT_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		assertNull(signersDocument);
	}

}
