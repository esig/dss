package eu.europa.esig.dss.asic.signature.asics;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractASiCSGetDataToSign {

	private final static String ZIP_ENTRY_DETACHED_FILE = "detached-file";

	protected String getSignatureFileName(final ASiCParameters asicParameters) {
		if (Utils.isStringNotBlank(asicParameters.getSignatureFileName())) {
			return "META-INF/" + asicParameters.getSignatureFileName();
		}
		return "META-INF/signature.p7s";
	}

	protected DSSDocument createPackageZip(List<DSSDocument> documents) {
		ByteArrayOutputStream baos = null;
		ZipOutputStream zos = null;
		try {
			baos = new ByteArrayOutputStream();
			zos = new ZipOutputStream(baos);
			storeSignedFiles(documents, zos);
		} catch (IOException e) {
			throw new DSSException("Unable to create package.zip file", e);
		} finally {
			Utils.closeQuietly(zos);
			Utils.closeQuietly(baos);
		}
		return new InMemoryDocument(baos.toByteArray(), "package.zip");
	}

	protected void storeSignedFiles(final List<DSSDocument> documents, final ZipOutputStream zos) throws IOException {
		for (DSSDocument document : documents) {
			InputStream is = null;
			try {
				final String documentName = document.getName();
				final String name = documentName != null ? documentName : ZIP_ENTRY_DETACHED_FILE;
				final ZipEntry entryDocument = new ZipEntry(name);
				zos.setLevel(ZipEntry.DEFLATED);

				zos.putNextEntry(entryDocument);
				is = document.openStream();
				Utils.copy(is, zos);
			} finally {
				Utils.closeQuietly(is);
			}
		}
	}

}
