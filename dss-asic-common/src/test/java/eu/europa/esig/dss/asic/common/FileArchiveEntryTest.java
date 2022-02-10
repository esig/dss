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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class FileArchiveEntryTest {

    @Test
    public void test() throws IOException {
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
    }

}
