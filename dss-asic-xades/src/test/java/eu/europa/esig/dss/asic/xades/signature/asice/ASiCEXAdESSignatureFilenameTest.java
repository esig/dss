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

import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.signature.SimpleASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

class ASiCEXAdESSignatureFilenameTest extends ASiCEXAdESLevelBTest {

	private DSSDocument documentToSign;

	@TempDir
	static Path temporaryFolder;

	@BeforeEach
	void setUp() throws Exception {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");
	}

	@Test
	@Override
	public void signAndVerify() {
		Path containerTemporaryPath = temporaryFolder.resolve("container.asice");

		ASiCWithXAdESService service = (ASiCWithXAdESService) getService();
		SimpleASiCWithXAdESFilenameFactory asicFilenameFactory = new SimpleASiCWithXAdESFilenameFactory();
		asicFilenameFactory.setSignatureFilename("signatures2047.xml");
		service.setAsicFilenameFactory(asicFilenameFactory);

		documentToSign = sign();
		try {
			documentToSign.save(containerTemporaryPath.toString());
		} catch (IOException e) {
			fail("Unable to save document", e);
		}
		try (ZipFile zip = new ZipFile(containerTemporaryPath.toString())) {
			assertNotNull(zip.getEntry("META-INF/signatures2047.xml"), "Signature file name is not correct");
		} catch (IOException e) {
			fail("Unable to retrieve entry", e);
		}
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

}
