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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.SignatureCertificateSource;

import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS2023Test extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades3_Baseline_B.pdf"));
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		for (AdvancedSignature advancedSignature : advancedSignatures) {
			SignatureCertificateSource certificateSource = advancedSignature.getCertificateSource();
			
			SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(advancedSignature.getId());
			FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
			
			assertEquals(new HashSet<>(certificateSource.getDSSDictionaryCertValues()).size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size());
		}
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		for (SignatureWrapper signatureWrapper : signatures) {
			if (Utils.isCollectionNotEmpty(signatureWrapper.getTimestampList())) {
				assertTrue(diagnosticData.isTLevelTechnicallyValid(signatureWrapper.getId()));
				assertTrue(diagnosticData.isALevelTechnicallyValid(signatureWrapper.getId()));
			} else {
				assertFalse(diagnosticData.isTLevelTechnicallyValid(signatureWrapper.getId()));
				assertFalse(diagnosticData.isALevelTechnicallyValid(signatureWrapper.getId()));
			}
		}
	}

}
