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
