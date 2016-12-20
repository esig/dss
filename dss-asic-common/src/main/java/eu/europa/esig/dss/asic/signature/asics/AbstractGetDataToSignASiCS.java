package eu.europa.esig.dss.asic.signature.asics;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractGetDataToSignASiCS {

	private static final String ZIP_ENTRY_DETACHED_FILE = "detached-file";

	/* In case of multi-files and ASiC-S, we need to create a zip with all files to be signed */
	protected DSSDocument createPackageZip(List<DSSDocument> documents, Date signingDate) {
		ByteArrayOutputStream baos = null;
		ZipOutputStream zos = null;
		try {
			baos = new ByteArrayOutputStream();
			zos = new ZipOutputStream(baos);

			for (DSSDocument document : documents) {
				final String documentName = document.getName();
				final String name = documentName != null ? documentName : ZIP_ENTRY_DETACHED_FILE;
				final ZipEntry entryDocument = new ZipEntry(name);
				entryDocument.setTime(signingDate.getTime());
				entryDocument.setMethod(ZipEntry.STORED);
				byte[] byteArray = DSSUtils.toByteArray(document);
				entryDocument.setSize(byteArray.length);
				entryDocument.setCompressedSize(byteArray.length);
				final CRC32 crc = new CRC32();
				crc.update(byteArray);
				entryDocument.setCrc(crc.getValue());
				zos.putNextEntry(entryDocument);
				Utils.write(byteArray, zos);
			}

		} catch (IOException e) {
			throw new DSSException("Unable to create package.zip file", e);
		} finally {
			Utils.closeQuietly(zos);
			Utils.closeQuietly(baos);
		}
		return new InMemoryDocument(baos.toByteArray(), "package.zip");
	}

}
