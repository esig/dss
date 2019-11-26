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
package eu.europa.esig.dss.pades.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.test.validation.AbstractTestValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class PDFDocumentValidatorCheckTest extends AbstractTestValidator {

	@Test
	public void isSupported() {
		PDFDocumentValidator validator = new PDFDocumentValidator();
		
		byte[] wrongBytes = new byte[] { 1, 2 };
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes)));
		assertFalse(validator.isSupported(new InMemoryDocument(new byte[] { '<', '?', 'x', 'm', 'l' })));
		assertFalse(validator.isSupported(new InMemoryDocument(new byte[] { '%' })));
		assertFalse(validator.isSupported(new InMemoryDocument(new byte[] { 'P', 'D', 'F' })));
		
		assertTrue(validator.isSupported(new InMemoryDocument(new byte[] { '%', 'P', 'D', 'F', '-' })));
		assertTrue(validator.isSupported(new InMemoryDocument(new byte[] { '%', 'P', 'D', 'F', '-', '1', '.', '4' })));
	}

	@Override
	protected SignedDocumentValidator initEmptyValidator() {
		return new PDFDocumentValidator();
	}

	@Override
	protected SignedDocumentValidator initValidator(DSSDocument document) {
		return new PDFDocumentValidator(document);
	}

	@Override
	protected List<DSSDocument> getValidDocuments() {
		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		documents.add(new InMemoryDocument(getClass().getResourceAsStream("/validation/pdf-signed-original.pdf")));
		documents.add(new InMemoryDocument(getClass().getResourceAsStream("/validation/PAdES-LTA.pdf")));
		documents.add(new InMemoryDocument(getClass().getResourceAsStream("/validation/encrypted.pdf")));
		return documents;
	}

	@Override
	protected DSSDocument getMalformedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/malformed-pades.pdf"));
	}

	@Override
	protected DSSDocument getOtherTypeDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"));
	}

	@Override
	protected DSSDocument getNoSignatureDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));
	}

}
