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
package eu.europa.esig.dss.xades.validation.dss1524;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS1524WrongAttachmentTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/sig_bundle.signed_detached.xml");
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Arrays.<DSSDocument>asList(new InMemoryDocument(new byte[] { 1, 2, 3 }));
	}
	
	@Override
	protected void checkSignatureScopes(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(0, signatureWrapper.getSignatureScopes().size());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signatureWrapper.isSignatureIntact());
		assertFalse(signatureWrapper.isBLevelTechnicallyValid());
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertFalse(timestampWrapper.isMessageImprintDataIntact());
				assertFalse(timestampWrapper.isMessageImprintDataIntact());
			}
		}
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		assertTrue(Utils.isCollectionEmpty(originalDocuments));
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		// Unable to validate archive timestamp with a digest document
		assertFalse(signatureWrapper.isALevelTechnicallyValid());
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(1, diagnosticData.getAllOrphanRevocationObjects().size());
	}
	
	@Override
	protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
		assertNull(signersDocument);
	}

}
