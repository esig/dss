package eu.europa.esig.dss.asic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class is used to read an ASiC Container and to retrieve its content files
 */
public abstract class AbstractASiCContainerExtractor {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractASiCContainerExtractor.class);

	private static final String MIME_TYPE = "mimetype";
	protected static final String META_INF_FOLDER = "META-INF/";

	private final DSSDocument asicContainer;

	protected AbstractASiCContainerExtractor(DSSDocument asicContainer) {
		this.asicContainer = asicContainer;
	}

	public ASiCExtractResult extract() {
		ASiCExtractResult result = new ASiCExtractResult();

		try (InputStream is = asicContainer.openStream(); ZipInputStream asicInputStream = new ZipInputStream(is)) {
			ZipEntry entry;
			while ((entry = asicInputStream.getNextEntry()) != null) {
				String entryName = entry.getName();
				if (isMetaInfFolder(entryName)) {
					if (isAllowedSignature(entryName)) {
						result.getSignatureDocuments().add(getCurrentDocument(entryName, asicInputStream));
					} else if (isAllowedManifest(entryName)) {
						result.getManifestDocuments().add(getCurrentDocument(entryName, asicInputStream));
					} else if (isAllowedArchiveManifest(entryName)) {
						result.getArchiveManifestDocuments().add(getCurrentDocument(entryName, asicInputStream));
					} else if (isAllowedTimestamp(entryName)) {
						result.getTimestampDocuments().add(getCurrentDocument(entryName, asicInputStream));
					} else if (!isFolder(entryName)) {
						result.getUnsupportedDocuments().add(getCurrentDocument(entryName, asicInputStream));
					}
				} else if (!isFolder(entryName)) {
					if (isMimetype(entryName)) {
						result.setMimeTypeDocument(getCurrentDocument(entryName, asicInputStream));
					} else {
						result.getSignedDocuments().add(getCurrentDocument(entryName, asicInputStream));
					}
				} else {
					result.getUnsupportedDocuments().add(getCurrentDocument(entryName, asicInputStream));
				}
			}

			if (Utils.isCollectionNotEmpty(result.getUnsupportedDocuments())) {
				LOG.warn("Unsupported files : " + result.getUnsupportedDocuments());
			}

		} catch (IOException e) {
			LOG.warn("Unable to parse the container " + e.getMessage());
		}

		result.setZipComment(getZipComment());

		return result;
	}

	public String getZipComment() {
		try (InputStream is = asicContainer.openStream()) {
			byte[] buffer = Utils.toByteArray(is);
			final int len = buffer.length;
			final byte[] magicDirEnd = { 0x50, 0x4b, 0x05, 0x06 };

			// Check the buffer from the end
			for (int ii = len - magicDirEnd.length - 22; ii >= 0; ii--) {
				boolean isMagicStart = true;
				for (int jj = 0; jj < magicDirEnd.length; jj++) {
					if (buffer[ii + jj] != magicDirEnd[jj]) {
						isMagicStart = false;
						break;
					}
				}
				if (isMagicStart) {
					// Magic Start found!
					int commentLen = buffer[ii + 20] + buffer[ii + 21] * 256;
					int realLen = len - ii - 22;
					if (commentLen != realLen) {
						LOG.warn("WARNING! ZIP comment size mismatch: directory says len is " + commentLen + ", but file ends after " + realLen + " bytes!");
					}
					return new String(buffer, ii + 22, realLen);

				}
			}
		} catch (Exception e) {
			LOG.warn("Unable to extract the ZIP comment : " + e.getMessage());
		}
		return null;
	}

	private boolean isMimetype(String entryName) {
		return MIME_TYPE.equals(entryName);
	}

	private boolean isMetaInfFolder(String entryName) {
		return entryName.startsWith(META_INF_FOLDER);
	}

	private boolean isFolder(String entryName) {
		return entryName.endsWith("/");
	}

	abstract boolean isAllowedManifest(String entryName);

	abstract boolean isAllowedArchiveManifest(String entryName);

	abstract boolean isAllowedTimestamp(String entryName);

	abstract boolean isAllowedSignature(String entryName);

	private DSSDocument getCurrentDocument(String filepath, ZipInputStream zis) throws IOException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			Utils.copy(zis, baos);
			baos.flush();
			return new InMemoryDocument(baos.toByteArray(), filepath);
		}
	}

}
