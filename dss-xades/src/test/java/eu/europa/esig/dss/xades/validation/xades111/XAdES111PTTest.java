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
package eu.europa.esig.dss.xades.validation.xades111;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

public class XAdES111PTTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-X-PT-4.xml");
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signatureById.getDigestMatchers();
		assertEquals(2, digestMatchers.size());
		assertFalse(signatureById.isSignatureIntact());
		assertFalse(signatureById.isSignatureValid());
		assertTrue(signatureById.isSigningCertificateIdentified());
		assertFalse(signatureById.isSignatureProductionPlacePresent());
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> signatures, DiagnosticData diagnosticData) {
		AdvancedSignature advancedSignature = signatures.get(0);
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(advancedSignature.getId());

		SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
		FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
		
		assertEquals(certificateSource.getCompleteCertificateRefs().size(),
				foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size() +
				foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isThereTLevel(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isThereALevel(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		assertEquals(3, diagnosticData.getTimestampList().size());
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(1, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}

	@Override
	protected void checkStructureValidation(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signatureWrapper.isStructuralValidationValid());
		assertEquals(2, signatureWrapper.getStructuralValidationMessages().size());
		
		boolean crlValuesOrderErrorFound = false;
		for (String error : signatureWrapper.getStructuralValidationMessages()) {
			if (error.contains("\"http://uri.etsi.org/01903/v1.3.2#\":CRLValues")) {
				crlValuesOrderErrorFound = true;
			}
		}
		assertTrue(crlValuesOrderErrorFound);
	}

}
