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
package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;

class XAdESNoSignedPropertiesTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss-signed-altered-signedPropsRemoved.xml");
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		XmlDigestMatcher signedPropertiesDigest = null;
		XmlDigestMatcher refDigest = null;
		
		assertNotNull(digestMatchers);
		assertEquals(1, digestMatchers.size());

		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			if (DigestMatcherType.SIGNED_PROPERTIES == xmlDigestMatcher.getType()) {
				signedPropertiesDigest = xmlDigestMatcher;
			} else if (DigestMatcherType.REFERENCE == xmlDigestMatcher.getType()) {
				refDigest = xmlDigestMatcher;
			} else {
				fail("Unexpected " + xmlDigestMatcher.getType());
			}
		}

		assertNull(signedPropertiesDigest);
		assertNotNull(refDigest);
		assertTrue(refDigest.isDataFound());
		assertTrue(refDigest.isDataIntact());
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);
		
		assertEquals(Indication.INDETERMINATE,
				detailedReport.getBasicBuildingBlocksIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE,
				detailedReport.getBasicBuildingBlocksSubIndication(detailedReport.getFirstSignatureId()));
	}
	
	@Override
	protected void verifySimpleReport(SimpleReport simpleReport) {
		super.verifySimpleReport(simpleReport);
		
		assertEquals(Indication.TOTAL_FAILED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CRYPTO_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

}
