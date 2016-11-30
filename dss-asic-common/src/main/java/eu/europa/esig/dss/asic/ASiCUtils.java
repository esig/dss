package eu.europa.esig.dss.asic;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.utils.Utils;

public final class ASiCUtils {

	private static final String MIME_TYPE = "mimetype";
	private static final String MIME_TYPE_COMMENT = MIME_TYPE + "=";
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

	public static boolean isASiCMimeType(final MimeType asicMimeType) {
		return MimeType.ASICS.equals(asicMimeType) || MimeType.ASICE.equals(asicMimeType);
	}

	public static ASiCContainerType getASiCContainerType(final MimeType asicMimeType) {
		if (MimeType.ASICS == asicMimeType) {
			return ASiCContainerType.ASiC_S;
		} else if (MimeType.ASICE == asicMimeType) {
			return ASiCContainerType.ASiC_E;
		} else {
			throw new IllegalArgumentException("Not allowed mimetype " + asicMimeType);
		}
	}

	public static boolean isASiCE(final ASiCParameters asicParameters) {
		return ASiCContainerType.ASiC_E.equals(asicParameters.getContainerType());
	}

	public static boolean isASiCS(final ASiCParameters asicParameters) {
		return ASiCContainerType.ASiC_S.equals(asicParameters.getContainerType());
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

	public static boolean isASiCManifestWithCAdES(String entryName) {
		final boolean manifest = entryName.startsWith(META_INF_FOLDER + "ASiCManifest") && entryName.endsWith(".xml");
		return manifest;
	}

	public static boolean isASiCManifestWithXAdES(String entryName) {
		final boolean manifest = entryName.equals(META_INF_FOLDER + "manifest.xml");
		return manifest;
	}

	public static boolean isXAdES(final String entryName) {
		final boolean signature = isSignature(entryName) && entryName.endsWith(".xml");
		return signature;
	}

	public static boolean isCAdES(final String entryName) {
		final boolean signature = isSignature(entryName) && (entryName.endsWith(".p7s") || entryName.endsWith(".p7m"));
		return signature;
	}

	public static boolean isMetaInfFolder(String entryName) {
		return entryName.startsWith(META_INF_FOLDER);
	}

	public static boolean isFolder(String entryName) {
		return entryName.endsWith("/");
	}

	public static MimeType getMimeType(final DSSDocument mimeTypeDocument) throws DSSException {
		InputStream is = null;
		try {
			is = mimeTypeDocument.openStream();
			byte[] byteArray = Utils.toByteArray(is);
			final String mimeTypeString = new String(byteArray, "UTF-8");
			return MimeType.fromMimeTypeString(mimeTypeString);
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {
			Utils.closeQuietly(is);
		}
	}

	public static ASiCContainerType getContainerType(DSSDocument archive, DSSDocument mimetype, String zipComment) {
		ASiCContainerType containerType = null;
		MimeType mimeTypeFromContainer = archive.getMimeType();
		if (ASiCUtils.isASiCMimeType(mimeTypeFromContainer)) {
			containerType = ASiCUtils.getASiCContainerType(mimeTypeFromContainer);
		} else if (mimetype != null) {
			MimeType mimeTypeFromEmbeddedFile = ASiCUtils.getMimeType(mimetype);
			if (ASiCUtils.isASiCMimeType(mimeTypeFromEmbeddedFile)) {
				containerType = ASiCUtils.getASiCContainerType(mimeTypeFromEmbeddedFile);
			}
		} else if (zipComment != null) {
			int indexOf = zipComment.indexOf(MIME_TYPE_COMMENT);
			if (indexOf > -1) {
				String asicCommentMimeTypeString = zipComment.substring(MIME_TYPE_COMMENT.length() + indexOf);
				MimeType mimeTypeFromZipComment = MimeType.fromMimeTypeString(asicCommentMimeTypeString);
				if (ASiCUtils.isASiCMimeType(mimeTypeFromZipComment)) {
					containerType = ASiCUtils.getASiCContainerType(mimeTypeFromZipComment);
				}
			}
		}
		return containerType;
	}

}
