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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.test.validation.AbstractTestValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XMLDocumentValidatorTest extends AbstractTestValidator {

	@Test
	public void isSupported() {
		XMLDocumentValidator validator = new XMLDocumentValidator();
		
		byte[] wrongBytes = new byte[] { 1, 2 };
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes)));
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.PDF)));
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test")));
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.XML)));
		assertFalse(validator.isSupported(new InMemoryDocument(wrongBytes, "test.xml")));
		
		assertTrue(validator.isSupported(new InMemoryDocument(new byte[] { '<', '?', 'x', 'm', 'l' })));
		assertTrue(validator.isSupported(new InMemoryDocument(new byte[] { -17, -69, -65, '<' })));
		assertTrue(validator.isSupported(new InMemoryDocument(new byte[] { '<', 'd', 's', ':' })));
	}

	@Override
	protected SignedDocumentValidator initEmptyValidator() {
		return new XMLDocumentValidator();
	}

	@Override
	protected SignedDocumentValidator initValidator(DSSDocument document) {
		return new XMLDocumentValidator(document);
	}

	@Override
	protected List<DSSDocument> getValidDocuments() {
		List<DSSDocument> documents = new ArrayList<>();
		documents.add(new FileDocument("src/test/resources/validation/dss-signed.xml"));
		documents.add(new FileDocument("src/test/resources/validation/valid-xades.xml"));
		documents.add(new FileDocument("src/test/resources/validation/xades-x-level.xml"));
		documents.add(new FileDocument("src/test/resources/validation/valid.xades"));
		return documents;
	}

	@Override
	protected DSSDocument getMalformedDocument() {
		return new FileDocument("src/test/resources/validation/malformed-xades.xml");
	}

	@Override
	protected DSSDocument getOtherTypeDocument() {
		return new FileDocument("src/test/resources/sample.png");
	}

	@Override
	protected DSSDocument getNoSignatureDocument() {
		return new FileDocument("src/test/resources/sample.xml");
	}

	@Override
	protected DSSDocument getXmlEvidenceRecordDocument() {
		return new FileDocument("src/test/resources/validation/evidence-record/evidence-record-5b5edd31-344d-4d66-8e95-79f9acaab566.xml");
	}

}
