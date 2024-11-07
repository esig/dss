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

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class XAdESNoReferenceTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss-signed-altered-refRemoved.xml");
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		SignatureWrapper signatureWrapper = signatures.get(0);
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		XmlDigestMatcher signedPropertiesDigest = null;
		XmlDigestMatcher refDigest = null;

		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			if (DigestMatcherType.SIGNED_PROPERTIES == xmlDigestMatcher.getType()) {
				signedPropertiesDigest = xmlDigestMatcher;
			} else if (DigestMatcherType.REFERENCE == xmlDigestMatcher.getType()) {
				refDigest = xmlDigestMatcher;
			} else {
				fail("Unexpected " + xmlDigestMatcher.getType());
			}
		}

		assertNotNull(signedPropertiesDigest);
		assertTrue(signedPropertiesDigest.isDataFound());
		assertTrue(signedPropertiesDigest.isDataIntact());
		assertNotNull(refDigest);
		assertFalse(refDigest.isDataFound());
		assertFalse(refDigest.isDataIntact());
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		List<SignerDataWrapper> originalSignerDocuments = diagnosticData.getOriginalSignerDocuments();
		assertTrue(Utils.isCollectionEmpty(originalSignerDocuments));
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);
		assertEquals(SignatureLevel.XML_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}

	@Override
	protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
		// signed data reference is not present
	}
	
	@Override
	protected void verifyDetailedReport(DetailedReport detailedReport) {
		super.verifyDetailedReport(detailedReport);

		assertEquals(Indication.INDETERMINATE,
				detailedReport.getFinalIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND,
				detailedReport.getFinalSubIndication(detailedReport.getFirstSignatureId()));
	}
	
	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		assertNull(signersDocument);
	}

}
