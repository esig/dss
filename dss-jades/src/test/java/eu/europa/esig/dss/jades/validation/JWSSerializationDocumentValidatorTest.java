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
package eu.europa.esig.dss.jades.validation;

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

public class JWSSerializationDocumentValidatorTest extends AbstractTestValidator {

	@Test
	public void test() {
		JWSSerializationDocumentValidator validator = new JWSSerializationDocumentValidator();
		assertFalse(validator.isSupported(new InMemoryDocument(new byte[] {})));
		assertFalse(validator.isSupported(InMemoryDocument.createEmptyDocument()));
		assertFalse(validator.isSupported(new InMemoryDocument("{".getBytes())));
		assertTrue(validator.isSupported(new InMemoryDocument("{}".getBytes())));
		assertFalse(validator.isSupported(new InMemoryDocument("{hello:\"world\"}".getBytes())));
		assertTrue(validator.isSupported(new InMemoryDocument("{\"hello\":\"world\"}".getBytes())));
		assertTrue(validator.isSupported(new InMemoryDocument("{\"payload\":\"AAA\",\"signatures\":[{\"protected\":\"BBB\",\"signature\":\"CCCC\"}]}".getBytes())));
	}

	@Override
	protected SignedDocumentValidator initEmptyValidator() {
		return new JWSSerializationDocumentValidator();
	}

	@Override
	protected SignedDocumentValidator initValidator(DSSDocument document) {
		return new JWSSerializationDocumentValidator(document);
	}

	@Override
	protected List<DSSDocument> getValidDocuments() {
		List<DSSDocument> documents = new ArrayList<>();
		documents.add(new FileDocument("src/test/resources/validation/jades-lta.json"));
		documents.add(new FileDocument("src/test/resources/validation/jades-with-counter-signature.json"));
		documents.add(new FileDocument("src/test/resources/validation/serialization-extra-element.json"));
		return documents;
	}

	@Override
	protected DSSDocument getMalformedDocument() {
		return new FileDocument("src/test/resources/validation/malformed-jades-serialization.json");
	}

	@Override
	protected DSSDocument getOtherTypeDocument() {
		return new FileDocument("src/test/resources/validation/jades-level-b-full-type.json");
	}

	@Override
	protected DSSDocument getNoSignatureDocument() {
		return new FileDocument("src/test/resources/validation/jws-serialization-no-signatures.json");
	}

	@Override
	protected DSSDocument getXmlEvidenceRecordDocument() {
		return new FileDocument("src/test/resources/validation/evidence-record/evidence-record-a0baac29-c2b6-4544-abc5-d26ac6c8b655.xml");
	}

}
