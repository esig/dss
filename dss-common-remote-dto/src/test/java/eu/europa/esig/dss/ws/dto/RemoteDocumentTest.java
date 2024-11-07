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
package eu.europa.esig.dss.ws.dto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

class RemoteDocumentTest {

	@Test
	void testDocNull() {
		RemoteDocument doc = new RemoteDocument();
		assertNotNull(doc.toString());
	}

	@Test
	void testEquals() {
		RemoteDocument doc1 = new RemoteDocument(new byte[] { 1, 2, 3 }, "bla");
		RemoteDocument doc2 = new RemoteDocument(new byte[] { 1, 2, 3 }, "bla");
		assertEquals(doc1, doc2);
		assertNotNull(doc1.toString());

		doc2.setDigestAlgorithm(DigestAlgorithm.SHA256);
		assertNotEquals(doc1, doc2);
		assertNotNull(doc2.toString());
		doc2.setDigestAlgorithm(null);
		assertEquals(doc1, doc2);

		doc2.setName("bli");
		assertNotEquals(doc1, doc2);
		doc2.setName("bla");
		assertEquals(doc1, doc2);

		doc2.setBytes(new byte[] { 0, 0, 0 });
		assertNotEquals(doc1, doc2);
		doc2.setBytes(new byte[] { 1, 2, 3 });
		assertEquals(doc1, doc2);
	}

}
