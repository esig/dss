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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.xmldsig.definition.XMLDSigElement;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ManifestBuilderTest {

	private static final Logger LOG = LoggerFactory.getLogger(ManifestBuilderTest.class);

	@Test
	public void testBuildManifest() throws IOException {
		List<DSSDocument> documents = new ArrayList<>();
		FileDocument file1 = new FileDocument("src/test/resources/sample.png");
		documents.add(file1);
		documents.add(new FileDocument("src/test/resources/sample.txt"));
		documents.add(new FileDocument("src/test/resources/sample.xml"));
		ManifestBuilder builder = new ManifestBuilder("manifest", DigestAlgorithm.SHA512, documents);

		DSSDocument document = builder.build();
		assertNotNull(document);
		assertEquals(MimeTypeEnum.XML, document.getMimeType());

		try (InputStream is = document.openStream()) {
			String xmlContent = new String(Utils.toByteArray(is), "UTF-8");
			assertTrue(xmlContent.contains(XMLDSigElement.MANIFEST.getTagName()));
			assertTrue(xmlContent.contains(file1.getName()));
			assertTrue(xmlContent.contains(file1.getDigest(DigestAlgorithm.SHA512)));
			LOG.info(xmlContent);
		}
	}
}
