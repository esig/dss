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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithXAdESManifestBuilderTest {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithXAdESManifestBuilderTest.class);

	@Test
	void test() {
		DSSDocument d1 = new InMemoryDocument("hello".getBytes(), "test.txt");
		DSSDocument d2 = new InMemoryDocument("world".getBytes(), "test.html");
		DSSDocument d3 = new InMemoryDocument("bye".getBytes(), "test.pdf");
		List<DSSDocument> documents = Arrays.asList(d1, d2, d3);
		ASiCEWithXAdESManifestBuilder builder = new ASiCEWithXAdESManifestBuilder();
		DSSDocument manifestDoc = builder.setDocuments(documents).build();
		String xmlContent = new String( DSSUtils.toByteArray(manifestDoc));
		LOG.info(xmlContent);

		// <?xml version="1.0" encoding="UTF-8" standalone="no"?>
//		<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
//			<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.etsi.asic-e+zip"/>
//			<manifest:file-entry manifest:full-path="test.txt" manifest:media-type="text/plain"/>
//			<manifest:file-entry manifest:full-path="test.html" manifest:media-type="text/html"/>
//			<manifest:file-entry manifest:full-path="test.pdf" manifest:media-type="application/pdf"/>
//		</manifest:manifest> 

		assertTrue(xmlContent.contains("xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\""));
		assertTrue(xmlContent.contains("manifest:full-path=\"test.txt\" manifest:media-type=\"text/plain\""));
		assertTrue(xmlContent.contains("manifest:full-path=\"test.html\" manifest:media-type=\"text/html\""));
		assertTrue(xmlContent.contains("manifest:full-path=\"test.pdf\" manifest:media-type=\"application/pdf\""));
		assertTrue(xmlContent.contains("manifest:media-type=\"application/vnd.etsi.asic-e+zip\""));
	}

	@Test
	void nullTest() {
		ASiCEWithXAdESManifestBuilder builder = new ASiCEWithXAdESManifestBuilder();

		Exception exception = assertThrows(NullPointerException.class, builder::build);
		assertEquals("Either DSSDocuments or ManifestEntries shall be provided!", exception.getMessage());

		builder.setDocuments(Collections.singletonList(null));
		exception = assertThrows(NullPointerException.class, builder::build);
		assertEquals("DSSDocument cannot be null!", exception.getMessage());

		builder.setEntries(Collections.singletonList(null));
		exception = assertThrows(IllegalArgumentException.class, builder::build);
		assertEquals("Either DSSDocuments or ManifestEntries shall be provided!", exception.getMessage());

		builder.setDocuments(null);
		exception = assertThrows(NullPointerException.class, builder::build);
		assertEquals("ManifestEntry cannot be null!", exception.getMessage());

		ManifestEntry manifestEntry = new ManifestEntry();
		builder.setEntries(Collections.singletonList(manifestEntry));
		exception = assertThrows(NullPointerException.class, builder::build);
		assertEquals("ManifestEntry#Uri cannot be null! Please define the document's name.", exception.getMessage());

		manifestEntry.setUri("entry.txt");
		DSSDocument manifest = builder.build();
		assertNotNull(manifest);

		String xmlContent = new String( DSSUtils.toByteArray(manifest));
		assertTrue(xmlContent.contains("xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\""));
		assertFalse(xmlContent.contains("manifest:full-path=\"entry.txt\" manifest:media-type=\"text/plain\""));
		assertTrue(xmlContent.contains("manifest:full-path=\"entry.txt\" manifest:media-type=\"application/octet-stream\""));
		assertTrue(xmlContent.contains("manifest:media-type=\"application/vnd.etsi.asic-e+zip\""));

		manifestEntry.setMimeType(MimeTypeEnum.TEXT);

		manifest = builder.build();
		xmlContent = new String( DSSUtils.toByteArray(manifest));
		assertTrue(xmlContent.contains("xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\""));
		assertTrue(xmlContent.contains("manifest:full-path=\"entry.txt\" manifest:media-type=\"text/plain\""));
		assertFalse(xmlContent.contains("manifest:full-path=\"entry.txt\" manifest:media-type=\"application/octet-stream\""));
		assertTrue(xmlContent.contains("manifest:media-type=\"application/vnd.etsi.asic-e+zip\""));
	}

}
