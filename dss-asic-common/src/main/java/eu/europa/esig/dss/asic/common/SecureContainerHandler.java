package eu.europa.esig.dss.asic.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

/**
 * The default implementation of {@code ZipContainerHandler}, providing
 * utilities to prevent a denial of service attacks, such as zip-bombing
 *
 */
public class SecureContainerHandler implements ZipContainerHandler {

	private static final Logger LOG = LoggerFactory.getLogger(SecureContainerHandler.class);

	/**
	 * Minimum file size to be analized on zip bombing
	 */
	private long threshold = 1000000; // 1 MB

	/**
	 * Maximum compression ratio.
	 */
	private long maxCompressionRatio = 100;

	/**
	 * Defines the maximal amount of files that can be inside a ZIP container
	 */
	private int maxAllowedFilesAmount = 1000;

	/**
	 * Max iteration over the zip entries
	 */
	private int maxMalformedFiles = 100;

	/**
	 * Internal variable used to calculate the extracted entries size
	 * 
	 * NOTE: shall be reset on every use
	 */
	private int byteCounter = 0;

	/**
	 * Sets the maximum allowed threshold after exceeding each the security checks
	 * are enforced
	 * 
	 * Default : 1000000 (1 MB)
	 * 
	 * @param threshold in bytes
	 */
	public void setThreshold(long threshold) {
		this.threshold = threshold;
	}

	/**
	 * Sets the maximum allowed compression ratio If the container compression ratio
	 * exceeds the value, an exception is being thrown
	 * 
	 * Default : 100
	 * 
	 * @param maxCompressionRatio
	 */
	public void setMaxCompressionRatio(long maxCompressionRatio) {
		this.maxCompressionRatio = maxCompressionRatio;
	}

	/**
	 * Sets the maximum allowed amount of files inside a container
	 * 
	 * Default : 1000
	 * 
	 * @param maxAllowedFilesAmount
	 */
	public void setMaxAllowedFilesAmount(int maxAllowedFilesAmount) {
		this.maxAllowedFilesAmount = maxAllowedFilesAmount;
	}

	/**
	 * Sets the maximum allowed amount of malformed files
	 * 
	 * Default : 100
	 * 
	 * @param maxMalformedFiles
	 */
	public void setMaxMalformedFiles(int maxMalformedFiles) {
		this.maxMalformedFiles = maxMalformedFiles;
	}

	@Override
	public List<DSSDocument> extractContainerContent(DSSDocument zipPackage) {
		resetByteCounter();

		List<DSSDocument> result = new ArrayList<>();
		long containerSize = DSSUtils.getFileByteSize(zipPackage);
		try (InputStream is = zipPackage.openStream(); ZipInputStream zis = new ZipInputStream(is)) {
			DSSDocument document;
			while ((document = getNextDocument(zis, containerSize)) != null) {
				result.add(document);
				assertCollectionSizeValid(result);
			}
		} catch (IOException e) {
			throw new DSSException("Unable to extract package.zip", e);
		}
		return result;
	}

	private DSSDocument getNextDocument(ZipInputStream zis, long containerSize) throws IOException {
		ZipEntry entry = getNextValidEntry(zis);
		if (entry != null) {
			DSSDocument currentDocument = getCurrentDocument(zis, containerSize);
			currentDocument.setName(entry.getName());
			return currentDocument;
		}
		return null;
	}

	@Override
	public List<String> extractEntryNames(DSSDocument zipPackage) {
		List<String> result = new ArrayList<>();
		try (InputStream is = zipPackage.openStream(); ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry entry;
			while ((entry = getNextValidEntry(zis)) != null) {
				result.add(entry.getName());
				assertCollectionSizeValid(result);
			}
		} catch (IOException e) {
			throw new DSSException("Unable to extract package.zip", e);
		}
		return result;
	}

	@Override
	public DSSDocument createZipArchive(List<DSSDocument> containerEntries, String zipComment) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
				ZipOutputStream zos = new ZipOutputStream(baos)) {

			for (DSSDocument entry : containerEntries) {
				final ZipEntry zipEntry = getZipEntry(entry);
				zos.putNextEntry(zipEntry);
				try (InputStream entryIS = entry.openStream()) {
					secureCopy(entryIS, zos, -1);
				}
			}
			if (Utils.isStringNotEmpty(zipComment)) {
				zos.setComment(zipComment);
			}
			zos.finish();

			return new InMemoryDocument(baos.toByteArray());

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to create an ASiC container. Reason : %s", e.getMessage()), e);
		}
	}

	private ZipEntry getZipEntry(DSSDocument entry) {
		if (ASiCUtils.isMimetype(entry.getName())) {
			return createMimeTypeZipEntry(entry);
		} else {
			return createDocumentZipEntry(entry);
		}
	}

	private ZipEntry createMimeTypeZipEntry(DSSDocument entry) {
		final ZipEntry entryMimetype = new ZipEntry(entry.getName());
		entryMimetype.setMethod(ZipEntry.STORED);
		final byte[] mimeTypeBytes = DSSUtils.toByteArray(entry);
		entryMimetype.setSize(mimeTypeBytes.length);
		entryMimetype.setCompressedSize(mimeTypeBytes.length);
		final CRC32 crc = new CRC32();
		crc.update(mimeTypeBytes);
		entryMimetype.setCrc(crc.getValue());
		return entryMimetype;
	}

	private ZipEntry createDocumentZipEntry(DSSDocument entry) {
		final String detachedDocumentName = entry.getName();
		final String entryName = detachedDocumentName != null ? detachedDocumentName
				: ASiCUtils.ZIP_ENTRY_DETACHED_FILE;
		final ZipEntry entryMimetype = new ZipEntry(entryName);
		entryMimetype.setMethod(ZipEntry.DEFLATED);
		return entryMimetype;
	}

	private void resetByteCounter() {
		byteCounter = 0;
	}

	/**
	 * Returns the next entry from the given ZipInputStream by skipping corrupted or
	 * not accessible files NOTE: returns null only when the end of ZipInputStream
	 * is reached
	 * 
	 * @param zis {@link ZipInputStream} to get next entry from
	 * @return list of file name {@link String}s
	 * @throws DSSException if too much tries failed
	 */
	private ZipEntry getNextValidEntry(ZipInputStream zis) {
		int counter = 0;
		while (counter < maxMalformedFiles) {
			try {
				return zis.getNextEntry();
			} catch (Exception e) {
				LOG.warn(
						"ZIP container contains a malformed, corrupted or not accessible entry! The entry is skipped. Reason: [{}]",
						e.getMessage());
				// skip the entry and continue until find the next valid entry or end of the
				// stream
				counter++;
				closeEntry(zis);
			}
		}
		throw new DSSException("Unable to retrieve a valid ZipEntry (" + maxMalformedFiles + " tries)");
	}

	/**
	 * This method closes the current Zip Entry. If an error occurs, a
	 * {@link DSSException} is thrown.
	 * 
	 * @param zis the {@link ZipInputStream}
	 */
	private void closeEntry(ZipInputStream zis) {
		try {
			zis.closeEntry();
		} catch (IOException e) {
			throw new DSSException("Unable to close entry", e);
		}
	}

	/**
	 * Returns file from the given ZipInputStream
	 * 
	 * @param zis           {@link ZipInputStream} of the file
	 * @param containerSize - long byte size of the parent container
	 * @return {@link DSSDocument} created from the given {@code zis}
	 * @throws IOException in case of ZipInputStream read error
	 */
	private DSSDocument getCurrentDocument(ZipInputStream zis, long containerSize) throws IOException {
		long allowedSize = containerSize * maxCompressionRatio;
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			secureCopy(zis, baos, allowedSize);
			baos.flush();
			return new InMemoryDocument(baos.toByteArray());
		} catch (IOException e) {
			closeEntry(zis);
			throw e;
		}
	}

	/**
	 * Reads and copies InputStream in a secure way, depending on the provided
	 * container size This method allows to detect "ZipBombing" (large files inside
	 * a zip container)
	 * 
	 * @param is          {@link InputStream} of file
	 * @param os          {@link OutputStream} where save file to
	 * @param allowedSize defines an allowed size of the ZIP container entries, if
	 *                    -1 skips the validation
	 */
	private void secureCopy(InputStream is, OutputStream os, long allowedSize) throws IOException {
		byte[] data = new byte[2048];
		int nRead;
		while ((nRead = is.read(data)) != -1) {
			byteCounter += nRead;
			assertExtractEntryLengthValid(allowedSize);
			os.write(data, 0, nRead);
		}
	}

	private void assertExtractEntryLengthValid(long allowedSize) {
		if (allowedSize != -1 && byteCounter > threshold && byteCounter > allowedSize) {
			throw new DSSException("Zip Bomb detected in the ZIP container. Validation is interrupted.");
		}
	}

	private void assertCollectionSizeValid(Collection<?> collection) {
		if (collection.size() > maxAllowedFilesAmount) {
			throw new DSSException("Too many files detected. Cannot extract ASiC content from the file.");
		}
	}

}
