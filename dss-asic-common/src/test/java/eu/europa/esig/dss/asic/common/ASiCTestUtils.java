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
package eu.europa.esig.dss.asic.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class ASiCTestUtils {

	public static void verifyZipContainer(DSSDocument document) {
		try (InputStream is = document.openStream();
				ZipInputStream zis = new ZipInputStream(is);
				ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			ZipEntry entry;
			while ((entry = zis.getNextEntry()) != null) {
				assertNotNull(entry.getName());
				assertNotEquals(-1L, entry.getTime());
				assertNull(entry.getExtra());

				if ("mimetype".equals(entry.getName())) {
					assertEquals(ZipEntry.STORED, entry.getMethod());
					assertNotEquals(-1, entry.getCrc());
					assertNotEquals(-1, entry.getSize());
					assertNotEquals(-1, entry.getCompressedSize());
				} else {
					// not defined values while not read
					assertEquals(ZipEntry.DEFLATED, entry.getMethod());
					assertEquals(-1, entry.getCrc());
					assertEquals(-1, entry.getSize());
					assertEquals(-1, entry.getCompressedSize());
				}

				// read the file in order to incorporate values for deflated entries
				byte[] buffer = new byte[8192];
				while (zis.read(buffer) > 0) {
					baos.write(buffer);
				}

				assertNotEquals(-1, entry.getCrc());
				assertNotEquals(-1, entry.getSize());
				assertNotEquals(-1, entry.getCompressedSize());

				if ("mimetype".equals(entry.getName())) {
					assertEquals(entry.getSize(), entry.getCompressedSize());
				} else {
					assertNotEquals(entry.getSize(), entry.getCompressedSize());
				}

				if ("package.zip".equals(entry.getName())) {
					verifyZipContainer(new InMemoryDocument(baos.toByteArray()));
				}

			}
		} catch (IOException e) {
			fail(e.getMessage());
		}
	}

}
