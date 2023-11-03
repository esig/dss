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

public class JWSCompactDocumentValidatorTest extends AbstractTestValidator {

	private static final DSSDocument JWS_SIGNATURE = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.2yUt5UtfsRK1pnN0KTTv7gzHTxwDqDz2OkFSqlbQ40A".getBytes());

	@Test
	public void test() {
		
		JWSCompactDocumentValidator validator = new JWSCompactDocumentValidator();

		DSSDocument jws = JWS_SIGNATURE;
		assertTrue(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA".getBytes());
		assertTrue(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9..c2lnaA".getBytes());
		assertTrue(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9..c2lnaA\n".getBytes());
		assertTrue(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9..c2lnaA\r\n".getBytes());
		assertTrue(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9..c2lnaA\n\n\n".getBytes());
		assertTrue(validator.isSupported(jws));

		DSSDocument wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA".getBytes());
		assertFalse(validator.isSupported(wrong));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9...c2lnaA".getBytes());
		assertFalse(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9..c2lnaA.c2lnaA".getBytes());
		assertFalse(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA.".getBytes());
		assertFalse(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9..c2lnaA.".getBytes());
		assertFalse(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9..c2lnaA ".getBytes());
		assertFalse(validator.isSupported(jws));
		jws = new InMemoryDocument("\neyJhbGciOiJIUzI1NiJ9..c2lnaA".getBytes());
		assertFalse(validator.isSupported(jws));
		jws = new InMemoryDocument(" eyJhbGciOiJIUzI1NiJ9..c2lnaA".getBytes());
		assertFalse(validator.isSupported(jws));
		jws = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.\n.c2lnaA".getBytes());
		assertFalse(validator.isSupported(jws));
		wrong = new InMemoryDocument("<".getBytes());
		assertFalse(validator.isSupported(wrong));
		wrong = new InMemoryDocument("%PDF".getBytes());
		assertFalse(validator.isSupported(wrong));
		wrong = new InMemoryDocument(new byte[] {});
		assertFalse(validator.isSupported(wrong));
		wrong = InMemoryDocument.createEmptyDocument();
		assertFalse(validator.isSupported(wrong));
	}
	
	@Override
	protected SignedDocumentValidator initEmptyValidator() {
		return new JWSCompactDocumentValidator();
	}

	@Override
	protected SignedDocumentValidator initValidator(DSSDocument document) {
		return new JWSCompactDocumentValidator(document);
	}

	@Override
	protected List<DSSDocument> getValidDocuments() {
		List<DSSDocument> documents = new ArrayList<>();
		documents.add(JWS_SIGNATURE);
		documents.add(new FileDocument("src/test/resources/validation/jades-level-b-full-type.json"));
		documents.add(new FileDocument("src/test/resources/validation/jades-with-asn1policy.json"));
		documents.add(new FileDocument("src/test/resources/validation/jades-with-certified.json"));
		return documents;
	}

	@Override
	protected DSSDocument getMalformedDocument() {
		return new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA..2yUt5UtfsRK1pnN0KTTv7gzHTxwDqDz2OkFSqlbQ40A".getBytes());
	}

	@Override
	protected DSSDocument getOtherTypeDocument() {
		return new FileDocument("src/test/resources/validation/jades-with-counter-signature.json");
	}

	@Override
	protected DSSDocument getNoSignatureDocument() {
		// not applicable
		return null;
	}

	@Override
	protected DSSDocument getXmlEvidenceRecordDocument() {
		return new FileDocument("src/test/resources/validation/evidence-record/evidence-record-a0baac29-c2b6-4544-abc5-d26ac6c8b655.xml");
	}

}
