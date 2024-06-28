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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileArchiveEntryTest {

    @Test
    void test() throws IOException {
        DSSDocument document = new InMemoryDocument("Hello World!".getBytes(), "doc");
        DSSDocument zipArchive = ZipUtils.getInstance().
                createZipArchive(Collections.singletonList(document), new Date(), null);

        String zipArchiveFilePath = "target/archive.zip";
        zipArchive.save(zipArchiveFilePath);

        File zipArchiveFile = new File(zipArchiveFilePath);
        assertTrue(zipArchiveFile.exists());

        FileDocument archive = new FileDocument(zipArchiveFilePath);

        List<? extends ZipEntry> entries;
        try (ZipFile zipFile = new ZipFile(archive.getFile())) {
            entries = Collections.list(zipFile.entries());
        }
        assertEquals(1, entries.size());

        FileArchiveEntry zipArchiveEntry = new FileArchiveEntry(archive, entries.get(0));

        // should be able to read more than once
        assertTrue(Utils.isArrayNotEmpty(DSSUtils.toByteArray(zipArchiveEntry)));
        assertTrue(Utils.isArrayNotEmpty(DSSUtils.toByteArray(zipArchiveEntry)));

        try (InputStream entryInputStream = zipArchiveEntry.openStream()) {
            entryInputStream.read();
            entryInputStream.close();

            // ensure the stream is closed
            assertThrows(IOException.class, () -> entryInputStream.read());
        }

        assertTrue(zipArchiveFile.delete());
        assertFalse(zipArchiveFile.exists());
    }

}
