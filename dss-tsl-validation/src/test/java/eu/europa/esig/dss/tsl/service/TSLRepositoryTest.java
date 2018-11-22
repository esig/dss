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
package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class TSLRepositoryTest {

	@Rule
	public TemporaryFolder folder = new TemporaryFolder();

	@Test
	public void clear() throws IOException {
		File testFolder = folder.newFolder("test");
		createFile(testFolder, "test1.xml");
		
		assertEquals(1, testFolder.listFiles().length);

		TSLRepository repo = new TSLRepository();
		repo.setCacheDirectoryPath(testFolder.getAbsolutePath());
		repo.clearRepository();
		assertEquals(0, testFolder.listFiles().length);
		assertTrue(testFolder.exists());
	}

	@Test(expected = FileNotFoundException.class)
	public void clearFolderNotExist() throws IOException {
		TSLRepository repo = new TSLRepository();
		repo.setCacheDirectoryPath("wrong");
		repo.clearRepository();
	}

	private void createFile(File folder, String name) throws IOException {
		File file = new File(folder, name);
		try (FileOutputStream fos = new FileOutputStream(file)) {
			fos.write(0);
		}
	}

}
