package eu.europa.esig.dss.asic;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.utils.Utils;

public final class ASiCUtils {

	private static final String MIME_TYPE = "mimetype";
	private static final String META_INF_FOLDER = "META-INF/";

	private ASiCUtils() {
	}

	public static boolean isMimetype(String entryName) {
		return MIME_TYPE.equalsIgnoreCase(entryName);
	}

	public static boolean isSignature(final String entryName) {
		final boolean signature = entryName.startsWith(META_INF_FOLDER) && entryName.contains("signature") && !entryName.contains("Manifest");
		return signature;
	}

	public static boolean isXAdES(final String entryName) {
		final boolean signature = isSignature(entryName) && entryName.endsWith(".xml");
		return signature;
	}

	public static boolean isCAdES(final String entryName) {
		final boolean signature = isSignature(entryName) && entryName.endsWith(".p7s");
		return signature;
	}

	public static boolean isASiCManifest(String entryName) {
		final boolean manifest = entryName.endsWith(".xml") && entryName.startsWith(META_INF_FOLDER + "ASiCManifest");
		return manifest;
	}

	public static String getMimeTypeString(final ASiCParameters asicParameters) {
		final String asicParameterMimeType = asicParameters.getMimeType();
		String mimeTypeString;
		if (Utils.isStringBlank(asicParameterMimeType)) {
			if (isASiCE(asicParameters)) {
				mimeTypeString = MimeType.ASICE.getMimeTypeString();
			} else {
				mimeTypeString = MimeType.ASICS.getMimeTypeString();
			}
		} else {
			mimeTypeString = asicParameterMimeType;
		}
		return mimeTypeString;
	}

	public static boolean isASiCE(final ASiCParameters asicParameters) {
		return ASiCContainerType.ASiC_E.equals(asicParameters.getContainerType());
	}

	public static MimeType getMimeType(ASiCParameters asicParameters) {
		return isASiCE(asicParameters) ? MimeType.ASICE : MimeType.ASICS;
	}

	public static boolean isArchiveContainsCorrectSignatureExtension(DSSDocument toSignDocument, String extension) {
		boolean isSignatureTypeCorrect = true;
		InputStream is = null;
		ZipInputStream zis = null;
		try {
			is = toSignDocument.openStream();
			zis = new ZipInputStream(is);
			ZipEntry entry;
			while ((entry = zis.getNextEntry()) != null) {
				if (isSignature(entry.getName())) {
					isSignatureTypeCorrect &= entry.getName().endsWith(extension);
				}
			}
		} catch (IOException e) {
			throw new DSSException("Unable to analyze the archive content", e);
		} finally {
			Utils.closeQuietly(zis);
			Utils.closeQuietly(is);
		}
		return isSignatureTypeCorrect;
	}

	public static boolean isArchive(DSSDocument doc) {
		return (doc.getName().endsWith(".zip") || doc.getName().endsWith(".bdoc") || doc.getName().endsWith(".asice") || doc.getName().endsWith(".asics"));
	}

	public static boolean isASiCContainer(DSSDocument dssDocument) {
		byte[] preamble = new byte[2];
		InputStream is = null;
		try {
			is = dssDocument.openStream();
			int r = is.read(preamble, 0, 2);
			if (r != 2) {
				return false;
			}
		} catch (IOException e) {
			throw new DSSException("Unable to read the 2 first bytes", e);
		} finally {
			Utils.closeQuietly(is);
		}

		return ((preamble[0] == 'P') && (preamble[1] == 'K'));
	}

}
