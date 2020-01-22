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
package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class CAdESWithGeneralizedSigningTimeTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/cades/CAdES-Baseline_Profile_B/Sample_Set_22/Signature-CBp-B-1.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		AdvancedSignature advancedSignature = signatures.get(0);
		assertNull(advancedSignature.getSigningTime());
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signatureWrapper);
		assertNull(signatureWrapper.getClaimedSigningTime());
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
