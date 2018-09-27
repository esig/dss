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
