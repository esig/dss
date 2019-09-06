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
package eu.europa.esig.dss.asic.xades.signature.asice;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.nio.file.Path;
import java.util.zip.ZipFile;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

public class ASiCEXAdESSignatureFilenameTest extends ASiCEXAdESLevelBTest {

	private DSSDocument documentToSign;

	@TempDir
    Path temporaryFolder;

	@BeforeEach
	public void setUp() throws Exception {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");
	}

	@Override
	public void signAndVerify() throws IOException {
		Path pathToFolder = temporaryFolder;
		String containerTemporaryPath = pathToFolder.toString();
		getSignatureParameters().aSiC().setSignatureFileName("signatures2047.xml");
		documentToSign = sign();
		documentToSign.save(containerTemporaryPath);
		ZipFile zip = new ZipFile(containerTemporaryPath);
		assertNotNull(zip.getEntry("META-INF/signatures2047.xml"), "Signature file name is not correct");
		Utils.closeQuietly(zip);
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

}
