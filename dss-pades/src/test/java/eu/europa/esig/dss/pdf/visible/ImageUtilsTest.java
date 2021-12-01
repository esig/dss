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
			assertTrue(ImageUtils.isTransparent(ImageUtils.toBufferedImage(fis)));
		}
	}

	@Test
	public void pngNoAlpha() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/signature-pen-no-alpha.png")) {
			assertFalse(ImageUtils.isTransparent(ImageUtils.toBufferedImage(fis)));
		}
	}

	@Test
	public void jpg() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/small-red.jpg")) {
			assertFalse(ImageUtils.isTransparent(ImageUtils.toBufferedImage(fis)));
		}
	}

}
