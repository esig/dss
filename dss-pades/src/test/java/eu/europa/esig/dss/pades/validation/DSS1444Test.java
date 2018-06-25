package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.IOException;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.FileDocument;

public class DSS1444Test {

	@Test
	public void test() throws Exception {
		File file = new File("src/test/resources/EmptyPage-corrupted.pdf");
		PDDocument doc = PDDocument.load(file);
		assertNotNull(doc);
	}

	@Test
	public void test2() throws Exception {
		File file = new File("src/test/resources/EmptyPage-corrupted2.pdf");
		PDDocument doc = PDDocument.load(file);
		assertNotNull(doc);
	}

	@Test(expected = IOException.class)
	public void test3() throws Exception {
		File file = new File("src/test/resources/small-red.jpg");
		PDDocument.load(file);
	}

	@Test(expected = DSSException.class)
	public void test3bis() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/small-red.jpg");
		PDFDocumentValidator val = new PDFDocumentValidator(dssDocument);
		val.getSignatures();
	}

}
