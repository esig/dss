package eu.europa.esig.dss.asic;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.ASiCContainerType;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.utils.Utils;

public final class ASiCUtils {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCUtils.class);

	private static final String MIME_TYPE = "mimetype";
	public static final String MIME_TYPE_COMMENT = MIME_TYPE + "=";
	private static final String META_INF_FOLDER = "META-INF/";

	private ASiCUtils() {
	}

	public static boolean isSignature(final String entryName) {
		return entryName.startsWith(META_INF_FOLDER) && entryName.contains("signature") && !entryName.contains("Manifest");
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
		return MimeType.ASICS.equals(asicMimeType) || MimeType.ASICE.equals(asicMimeType) || MimeType.ODT.equals(asicMimeType)
				|| MimeType.ODS.equals(asicMimeType);
	}

	public static ASiCContainerType getASiCContainerType(final MimeType asicMimeType) {
		if (MimeType.ASICS == asicMimeType) {
			return ASiCContainerType.ASiC_S;
		} else if (MimeType.ASICE == asicMimeType || MimeType.ODT == asicMimeType || MimeType.ODS.equals(asicMimeType)) {
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

	public static boolean isArchive(List<DSSDocument> docs) {
		if (Utils.collectionSize(docs) == 1) {
			return isASiCContainer(docs.get(0));
		}
		return false;
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

		return (preamble[0] == 'P') && (preamble[1] == 'K');
	}

	public static boolean isXAdES(final String entryName) {
		return isSignature(entryName) && entryName.endsWith(".xml");
	}

	public static boolean isCAdES(final String entryName) {
		return isSignature(entryName) && (entryName.endsWith(".p7s"));
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

	public static ASiCContainerType getContainerType(DSSDocument archive, DSSDocument mimetype, String zipComment, List<DSSDocument> signedDocuments) {
		ASiCContainerType containerType = getContainerTypeFromMimeType(archive.getMimeType());
		if (containerType == null) {
			containerType = getContainerTypeFromMimeTypeDocument(mimetype);
			if (containerType == null) {
				containerType = getContainerTypeFromZipComment(zipComment);
			}
		}

		if (containerType == null) {
			LOG.warn("Unable to define the ASiC Container type with its properties");
			if (Utils.collectionSize(signedDocuments) <= 1) {
				containerType = ASiCContainerType.ASiC_S;
			} else {
				containerType = ASiCContainerType.ASiC_E;
			}
		}

		return containerType;
	}

	private static ASiCContainerType getContainerTypeFromZipComment(String zipComment) {
		if (Utils.isStringNotBlank(zipComment)) {
			int indexOf = zipComment.indexOf(MIME_TYPE_COMMENT);
			if (indexOf > -1) {
				String asicCommentMimeTypeString = zipComment.substring(MIME_TYPE_COMMENT.length() + indexOf);
				MimeType mimeTypeFromZipComment = MimeType.fromMimeTypeString(asicCommentMimeTypeString);
				return getContainerTypeFromMimeType(mimeTypeFromZipComment);
			}
		}
		return null;
	}

	private static ASiCContainerType getContainerTypeFromMimeTypeDocument(DSSDocument mimetype) {
		if (mimetype != null) {
			MimeType mimeTypeFromEmbeddedFile = ASiCUtils.getMimeType(mimetype);
			return getContainerTypeFromMimeType(mimeTypeFromEmbeddedFile);
		}
		return null;
	}

	private static ASiCContainerType getContainerTypeFromMimeType(MimeType mimeType) {
		if (ASiCUtils.isASiCMimeType(mimeType)) {
			return ASiCUtils.getASiCContainerType(mimeType);
		}
		return null;
	}

}
