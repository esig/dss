package eu.europa.esig.dss.asic.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.FileDocument;

public class ASiCEWithXAdESManifestValidatorTest {

	@Test
	public void test() {
		FileDocument doc = new FileDocument(new File("src/test/resources/manifest-sample.xml"));
		ASiCEWithXAdESManifestValidator validator = new ASiCEWithXAdESManifestValidator(doc);

		List<String> coveredFiles = validator.getCoveredFiles();
		assertEquals(2, coveredFiles.size());
		assertTrue(coveredFiles.contains("test.txt"));
		assertTrue(coveredFiles.contains("test-data-file.bin"));
	}

}
