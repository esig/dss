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
package eu.europa.esig.dss.ws.converter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

public class RemoteDocumentConverterTest {
	
	@Test
	public void toDSSDocumentTest() {
		RemoteDocument remoteDocument = new RemoteDocument(new byte[] {'1','2','3'}, "remoteDocument");
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
		assertEquals(Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, remoteDocument.getBytes())), dssDocument.getDigest(DigestAlgorithm.SHA256));
		assertEquals(remoteDocument.getName(), dssDocument.getName());
	}
	
	@Test
	public void toDSSDigestDocumentTest() {
		RemoteDocument remoteDocument = new RemoteDocument(new byte[] {'1','2','3'}, DigestAlgorithm.SHA256, "remoteDocument");
		DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(remoteDocument);
		assertEquals(Utils.toBase64(remoteDocument.getBytes()), dssDocument.getDigest(remoteDocument.getDigestAlgorithm()));
		assertEquals(remoteDocument.getName(), dssDocument.getName());
	}
	
	@Test
	public void toDSSDocumentsTest() {
		List<RemoteDocument> remoteDocuments = new ArrayList<RemoteDocument>();
		remoteDocuments.add(new RemoteDocument(new byte[] {'1','2','3'}, "remoteDocument"));
		remoteDocuments.add(new RemoteDocument(new byte[] {'4','5','6'}, "remoteDocument2"));
		remoteDocuments.add(new RemoteDocument(null, null));
		remoteDocuments.add(null);
		List<DSSDocument> dssDocuments = RemoteDocumentConverter.toDSSDocuments(remoteDocuments);
		assertEquals(2, dssDocuments.size());
		assertEquals("remoteDocument", dssDocuments.get(0).getName());
		assertEquals("remoteDocument2", dssDocuments.get(1).getName());
	}
	
	@Test
	public void toRemoteDocumentTest() {
		DSSDocument dssDocument = new InMemoryDocument(new byte[] {'1','2','3'}, "dssDocument");
		RemoteDocument remoteDocument = RemoteDocumentConverter.toRemoteDocument(dssDocument);
		assertEquals(Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, remoteDocument.getBytes())), dssDocument.getDigest(DigestAlgorithm.SHA256));
		assertEquals(remoteDocument.getName(), dssDocument.getName());
	}
	
	@Test
	public void digestDocumentToRemoteDocumentTest() {
		DSSDocument dssDocument = new DigestDocument(DigestAlgorithm.SHA256, "332b7ce3b5e8f8c6132f0e09264db9da6d1c9fd6e37b73a35e68f78f4e590f90");
		RemoteDocument remoteDocument = RemoteDocumentConverter.toRemoteDocument(dssDocument);
		assertEquals(Utils.toBase64(remoteDocument.getBytes()), dssDocument.getDigest(remoteDocument.getDigestAlgorithm()));
		assertEquals(remoteDocument.getName(), dssDocument.getName());
	}
	
	@Test
	public void emptyDigestDocumentToRemoteDocumentTest() {
		DSSDocument dssDocument = new DigestDocument();
		assertThrows(DSSException.class, () -> RemoteDocumentConverter.toRemoteDocument(dssDocument));

		
	}
	
	@Test
	public void toRemoteDocumentsTest() {
		List<DSSDocument> dssDocuments = new ArrayList<DSSDocument>();
		dssDocuments.add(new InMemoryDocument(new byte[] {'1','2','3'}, "inMemoryDocument", MimeType.BINARY));
		dssDocuments.add(new InMemoryDocument(new byte[] {'1','2','3'}, "inMemoryDocument2"));
		dssDocuments.add(new DigestDocument(DigestAlgorithm.SHA256, "332b7ce3b5e8f8c6132f0e09264db9da6d1c9fd6e37b73a35e68f78f4e590f90", "digestDocument"));
		dssDocuments.add(null);
		List<RemoteDocument> remoteDocuments = RemoteDocumentConverter.toRemoteDocuments(dssDocuments);
		assertEquals(3, remoteDocuments.size());
		assertEquals("inMemoryDocument", remoteDocuments.get(0).getName());
		assertEquals("inMemoryDocument2", remoteDocuments.get(1).getName());
		assertEquals("digestDocument", remoteDocuments.get(2).getName());
	}

}
