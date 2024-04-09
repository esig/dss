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
package eu.europa.esig.dss.xades.validation.dss1334;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class DSS1334ValidationTest extends AbstractXAdESTestValidation {

	private static final DSSDocument ORIGINAL_FILE = new FileDocument("src/test/resources/validation/dss1334/simple-test.xml");
	
	@Test
	public void encodingTest() {
		// be careful about carriage returns windows/linux
		DSSDocument doc = new FileDocument("src/test/resources/validation/dss1334/simple-test.xml");
		assertEquals("tl08+/KLCeJN8RRCEDzF8aJ12Ew=", Utils.toBase64(doc.getDigestValue(DigestAlgorithm.SHA1)));
		// Hex content :
		// 3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d38223f3e0d0a3c746573743e0d0a093c74657374456c656d656e743e746573743c2f74657374456c656d656e743e0d0a3c2f746573743e0d0a
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss1334/document-signed-xades-baseline-b--null-for-filename.xml");
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Collections.singletonList(ORIGINAL_FILE);
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		// not valid : reference with empty URI -> not detached signature
		assertFalse(signature.isBLevelTechnicallyValid());
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		// reference is not valid
	}

}
