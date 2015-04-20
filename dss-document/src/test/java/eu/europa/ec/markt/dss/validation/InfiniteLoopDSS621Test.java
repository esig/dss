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
package eu.europa.ec.markt.dss.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.junit.Test;

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;

public class InfiniteLoopDSS621Test {

	@Test(timeout = 5000)
	public void testReadTimestamp1() throws Exception {
		DSSDocument signDocument = new FileDocument(new File("src/test/resources/validation/pades-5-signatures-and-1-document-timestamp.pdf"));
		final CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();

		final SignedDocumentValidator signedDocumentValidator = SignedDocumentValidator.fromDocument(signDocument);
		signedDocumentValidator.setCertificateVerifier(certificateVerifier);

		final List<AdvancedSignature> signatures = signedDocumentValidator.getSignatures();

		assertEquals(5, signatures.size());
		for (final AdvancedSignature signature : signatures) {
			// Not correct with BC 1.52, the signed attributes are not ordered
			// assertTrue(signature.checkSignatureIntegrity().isSignatureIntact());
			assertTrue(CollectionUtils.isNotEmpty(signature.getSignatureTimestamps()));
		}
	}

}
