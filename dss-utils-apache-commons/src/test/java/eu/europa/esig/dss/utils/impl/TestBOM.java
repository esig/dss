package eu.europa.esig.dss.utils.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.apache.commons.io.input.BOMInputStream;
import org.junit.Test;

public class TestBOM {

	@Test
	public void test() throws IOException {
		ApacheCommonsUtils acu = new ApacheCommonsUtils();

		FileInputStream fis = new FileInputStream(new File("src/test/resources/lotl_utf-8-sansbom.xml"));
		FileInputStream fisBom = new FileInputStream(new File("src/test/resources/lotl_utf-8.xml"));

		assertNotEquals(acu.toBase64(acu.toByteArray(fis)), acu.toBase64(acu.toByteArray(fisBom)));

		fis = new FileInputStream(new File("src/test/resources/lotl_utf-8-sansbom.xml"));
		fisBom = new FileInputStream(new File("src/test/resources/lotl_utf-8.xml"));

		BOMInputStream bomIS = new BOMInputStream(fis);
		BOMInputStream bomISSkipped = new BOMInputStream(fisBom);

		assertEquals(acu.toBase64(acu.toByteArray(bomIS)), acu.toBase64(acu.toByteArray(bomISSkipped)));
	}

}
