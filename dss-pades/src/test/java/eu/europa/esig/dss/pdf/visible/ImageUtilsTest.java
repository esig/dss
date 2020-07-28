package eu.europa.esig.dss.pdf.visible;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.FileInputStream;
import java.io.IOException;

import org.junit.jupiter.api.Test;

public class ImageUtilsTest {

	// http://exif.regex.info/exif.cgi

	@Test
	public void pngAlpha() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/signature-pen.png")) {
			assertTrue(ImageUtils.isTransparent(ImageUtils.read(fis)));
		}
	}

	@Test
	public void pngNoAlpha() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/signature-pen-no-alpha.png")) {
			assertFalse(ImageUtils.isTransparent(ImageUtils.read(fis)));
		}
	}

	@Test
	public void jpg() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/small-red.jpg")) {
			assertFalse(ImageUtils.isTransparent(ImageUtils.read(fis)));
		}
	}

}
