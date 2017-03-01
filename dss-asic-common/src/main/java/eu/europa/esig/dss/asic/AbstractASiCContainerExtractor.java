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

		ZipInputStream asicsInputStream = null;
		try {
			asicsInputStream = new ZipInputStream(asicContainer.openStream());
			ZipEntry entry;
			while ((entry = asicsInputStream.getNextEntry()) != null) {
				String entryName = entry.getName();
				if (isMetaInfFolder(entryName)) {
					if (isAllowedSignature(entryName)) {
						result.getSignatureDocuments().add(getCurrentDocument(entryName, asicsInputStream));
					} else if (isAllowedManifest(entryName)) {
						result.getManifestDocuments().add(getCurrentDocument(entryName, asicsInputStream));
					} else if (!isFolder(entryName)) {
						result.getUnsupportedDocuments().add(getCurrentDocument(entryName, asicsInputStream));
					}
				} else if (!isFolder(entryName)) {
					if (isMimetype(entryName)) {
						result.setMimeTypeDocument(getCurrentDocument(entryName, asicsInputStream));
					} else {
						result.getSignedDocuments().add(getCurrentDocument(entryName, asicsInputStream));
					}
				} else {
					result.getUnsupportedDocuments().add(getCurrentDocument(entryName, asicsInputStream));
				}
			}

			if (Utils.isCollectionNotEmpty(result.getUnsupportedDocuments())) {
				LOG.warn("Unsupported files : " + result.getUnsupportedDocuments());
			}

		} catch (IOException e) {
			LOG.warn("Unable to parse the container " + e.getMessage());
		} finally {
			Utils.closeQuietly(asicsInputStream);
		}

		result.setZipComment(getZipComment());

		return result;
	}

	public String getZipComment() {
		InputStream is = null;
		try {
			is = asicContainer.openStream();
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
		} finally {
			Utils.closeQuietly(is);
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

	abstract boolean isAllowedSignature(String entryName);

	private DSSDocument getCurrentDocument(String filepath, ZipInputStream zis) throws IOException {
		ByteArrayOutputStream baos = null;
		try {
			baos = new ByteArrayOutputStream();
			Utils.copy(zis, baos);
			return new InMemoryDocument(baos.toByteArray(), filepath);
		} finally {
			Utils.closeQuietly(baos);
		}
	}

}
