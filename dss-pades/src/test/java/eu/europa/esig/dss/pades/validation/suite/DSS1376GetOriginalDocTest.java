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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class DSS1376GetOriginalDocTest extends AbstractPAdESTestValidation {

	private static final Logger LOG = LoggerFactory.getLogger(DSS1376GetOriginalDocTest.class);

	private final DSSDocument revN = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1376/DSS1376-rev_n.pdf"));
	private final DSSDocument revN1 = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1376/DSS1376-rev_n-1.pdf"));

	@Override
	protected DSSDocument getSignedDocument() {
		return revN;
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);

		assertEquals(2, signatures.size());
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		List<AdvancedSignature> signatures = validator.getSignatures();

		AdvancedSignature firstSig = signatures.get(1);

		List<DSSDocument> originalDocuments = validator.getOriginalDocuments(firstSig.getId());
		assertEquals(1, originalDocuments.size());
		DSSDocument retrievedDoc = originalDocuments.get(0);
		LOG.debug("{} : {}", retrievedDoc.getName(), Utils.toBase64(retrievedDoc.getDigestValue(DigestAlgorithm.SHA256)));
		assertArrayEquals(revN1.getDigestValue(DigestAlgorithm.SHA256), retrievedDoc.getDigestValue(DigestAlgorithm.SHA256));

		AdvancedSignature secondSig = signatures.get(0);

		// Signature has been generated in the very first version of the PDF
		originalDocuments = validator.getOriginalDocuments(secondSig.getId());
		assertEquals(0, originalDocuments.size());
	}

	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		// skip (openpdf does not detect visual difference)
	}

}
