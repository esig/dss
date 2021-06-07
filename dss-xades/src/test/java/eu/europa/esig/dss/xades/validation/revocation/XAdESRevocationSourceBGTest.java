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
package eu.europa.esig.dss.xades.validation.revocation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESRevocationSourceBGTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-X-BG-1.xml");
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
		super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

		FoundCertificatesProxy foundCertificates = signature.foundCertificates();
		assertEquals(1, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.KEY_INFO).size());
		assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());
		assertEquals(1, foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).size());

		FoundRevocationsProxy foundRevocations = signature.foundRevocations();
		assertEquals(0, foundRevocations.getRelatedRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(1, foundRevocations.getOrphanRevocationsByOrigin(RevocationOrigin.REVOCATION_VALUES).size());
		assertEquals(0, foundRevocations.getRelatedRevocationRefs().size());
		assertEquals(0, foundRevocations.getOrphanRevocationRefs().size());
		assertEquals(0, foundRevocations.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
		assertEquals(0, foundRevocations.getRelatedRevocationsByRefOrigin(RevocationRefOrigin.ATTRIBUTE_REVOCATION_REFS).size());
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(1, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(1, diagnosticData.getAllOrphanRevocationObjects().size());
	}

	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		// do nothing
	}

	@Override
	protected void checkStructureValidation(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signatureWrapper.isStructuralValidationValid());
		assertEquals(6, signatureWrapper.getStructuralValidationMessages().size());

		boolean mixedSequenceOrderErrorFound = false;
		for (String error : signatureWrapper.getStructuralValidationMessages()) {
			if (error.contains("xades:StateOrProvince")) {
				mixedSequenceOrderErrorFound = true;
			}
		}
		assertTrue(mixedSequenceOrderErrorFound);
	}

}
