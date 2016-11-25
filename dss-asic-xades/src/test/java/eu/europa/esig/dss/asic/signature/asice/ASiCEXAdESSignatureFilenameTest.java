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
package eu.europa.esig.dss.asic.signature.asice;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.zip.ZipFile;

import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

public class ASiCEXAdESSignatureFilenameTest extends ASiCEXAdESLevelBTest {

	private DSSDocument documentToSign;

	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();

	@Before
	public void setUp() throws Exception {
		documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text");
	}

	@Override
	public void signAndVerify() throws IOException {
		String containerTemporaryPath = temporaryFolder.newFile().getPath();
		getSignatureParameters().aSiC().setSignatureFileName("signatures2047.xml");
		documentToSign = sign();
		documentToSign.save(containerTemporaryPath);
		ZipFile zip = new ZipFile(containerTemporaryPath);
		assertNotNull("Signature file name is not correct", zip.getEntry("META-INF/signatures2047.xml"));
		Utils.closeQuietly(zip);
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

}
