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

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * The default implementation of {@code ZipContainerHandler}, providing
 * utilities to prevent a denial of service attacks, such as zip-bombing
 *
 */
public class SecureContainerHandler implements ZipContainerHandler {

	private static final Logger LOG = LoggerFactory.getLogger(SecureContainerHandler.class);

	/**
	 * Minimum file size to be analyzed on zip bombing
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
	 * Internal variables used to count a number of malformed ZIP entries
	 *
	 * NOTE: shall be reset on every use
	 */
	private int malformedFilesCounter = 0;

	/**
	 * Defines whether comments of ZIP entries shall be extracted.
	 *
	 * Default : false (not extracted)
	 */
	private boolean extractComments = false;

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
	 * @param maxCompressionRatio the maximum compression ratio
	 */
	public void setMaxCompressionRatio(long maxCompressionRatio) {
		this.maxCompressionRatio = maxCompressionRatio;
	}

	/**
	 * Sets the maximum allowed amount of files inside a container
	 * 
	 * Default : 1000
	 * 
	 * @param maxAllowedFilesAmount the maximum number of allowed files
	 */
	public void setMaxAllowedFilesAmount(int maxAllowedFilesAmount) {
		this.maxAllowedFilesAmount = maxAllowedFilesAmount;
	}

	/**
	 * Sets the maximum allowed amount of malformed files
	 * 
	 * Default : 100
	 * 
	 * @param maxMalformedFiles the maximum number of malformed files
	 */
	public void setMaxMalformedFiles(int maxMalformedFiles) {
		this.maxMalformedFiles = maxMalformedFiles;
	}

	/**
	 * Sets whether comments of ZIP entries shall be extracted.
	 *
	 * Enabling of the feature can be useful when editing an existing archive,
	 * in order to preserve the existing data (i.e. comments).
	 * When enabled, slightly decreases the performance (about 10% for {@code extractContainerContent(zipArchive)} method).
	 *
	 * Reason : All ZIP entries from a ZIP archive are extracted using {@code java.util.zip.ZipInputStream},
	 * that is not able to extract comments for entries. In order to extract comments, the archive shall be read
	 * again using {@code java.util.zip.ZipFile}.
	 * For more information about limitations please see {@code <a href="https://stackoverflow.com/a/70848140">the link</a>}.
	 *
	 * Default : false (not extracted)
	 *
	 * @param extractComments whether comments shall be extracted
	 */
	public void setExtractComments(boolean extractComments) {
		this.extractComments = extractComments;
	}

	@Override
	public List<DSSDocument> extractContainerContent(DSSDocument zipArchive) {
		resetCounters();

		List<DSSDocument> result = new ArrayList<>();
		if (zipArchive instanceof FileDocument) {
			FileDocument zipFileDocument = (FileDocument) zipArchive;
			List<ZipEntry> zipEntries = extractZipEntries(zipFileDocument);
			if (!malformedEntriesDetected()) {
				for (ZipEntry zipEntry : zipEntries) {
					result.add(new FileArchiveEntry(zipFileDocument, zipEntry));
				}
				return result;

			} else {
				LOG.warn("The archive with name '{}' contains malformed entries. Unable to parse with ZipFile. " +
						"Continue with ZipInputStream...", zipArchive.getName());
			}
		}

		long containerSize = DSSUtils.getFileByteSize(zipArchive);
		try (InputStream is = zipArchive.openStream(); ZipInputStream zis = new ZipInputStream(is)) {
			DSSDocument document;
			while ((document = getNextDocument(zis, containerSize)) != null) {
				result.add(document);
				assertCollectionSizeValid(result);
			}
		} catch (IOException e) {
			throw new IllegalInputException("Unable to extract content from zip archive", e);
		}
		return result;
	}

	/**
	 * ZipFile object is not able to work with malformed archives.
	 * Therefore, we need to continue with ZipInputStream implementation when encountering a malformed ZIP archive.
	 *
	 * @return TRUE if the ZIP archive contains malformed ZIP entries, FALSE otherwise
	 */
	private boolean malformedEntriesDetected() {
		return malformedFilesCounter > 0;
	}

	private DSSDocument getNextDocument(ZipInputStream zis, long containerSize) {
		ZipEntry entry = getNextValidEntry(zis);
		if (entry != null) {
			return getCurrentEntryDocument(zis, entry, containerSize);
		}
		return null;
	}

	@Override
	public List<String> extractEntryNames(DSSDocument zipArchive) {
		List<ZipEntry> zipEntries = extractZipEntries(zipArchive);
		if (Utils.isCollectionNotEmpty(zipEntries)) {
			return zipEntries.stream().map(ZipEntry::getName).collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	private List<ZipEntry> extractZipEntries(DSSDocument zipArchive) {
		resetCounters();

		long containerSize = DSSUtils.getFileByteSize(zipArchive);
		long allowedSize = containerSize * maxCompressionRatio;

		/*
		 * Read with ZipInputStream in order to extract ZipEntry dates
		 */
		List<ZipEntry> result = new ArrayList<>();
		try (InputStream is = zipArchive.openStream(); ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry entry;
			while ((entry = getNextValidEntry(zis)) != null) {
				result.add(entry);
				assertCollectionSizeValid(result);
				secureRead(zis, allowedSize); // read securely before accessing the next entry
			}
		} catch (IOException e) {
			throw new IllegalArgumentException("Unable to extract entries from zip archive", e);
		}
		extractComments(zipArchive, result);
		return result;
	}

	private void extractComments(DSSDocument zipArchive, List<ZipEntry> zipEntries) {
		/*
		 * When reading a zip file using ZipInputStream, the comment is not available.
		 * See: https://bugs.openjdk.java.net/browse/JDK-4201267
		 *
		 * Therefore, we need to read comments with ZipFile, when possible
		 */
		if (extractComments && zipArchive instanceof FileDocument) {
			FileDocument fileDocument = (FileDocument) zipArchive;
			try (ZipFile zipFile = new ZipFile(fileDocument.getFile())) {
				for (ZipEntry zipEntry : zipEntries) {
					ZipEntry zipFileEntry = zipFile.getEntry(zipEntry.getName());
					zipEntry.setComment(zipFileEntry.getComment());
				}
			} catch (IOException e) {
				LOG.warn("Unable to read comments from zip archive", e);
			}
		}
	}

	@Override
	public DSSDocument createZipArchive(List<DSSDocument> containerEntries, Date creationTime, String zipComment) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
			 	ZipOutputStream zos = new ZipOutputStream(baos)) {

			for (DSSDocument entry : containerEntries) {
				final ZipEntry zipEntry = getZipEntry(entry, creationTime);
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

	private ZipEntry getZipEntry(DSSDocument entry, Date creationTime) {
		final DSSZipEntry zipEntryWrapper;
		if (entry instanceof DSSZipEntryDocument) {
			DSSZipEntryDocument dssZipEntry = (DSSZipEntryDocument) entry;
			zipEntryWrapper = dssZipEntry.getZipEntry();
		} else {
			zipEntryWrapper = new DSSZipEntry(entry.getName());
		}
		final ZipEntry zipEntry = zipEntryWrapper.createZipEntry();
		ensureCompressionMethod(zipEntry, entry);
		ensureTime(zipEntry, creationTime);
		return zipEntry;
	}

	private void ensureCompressionMethod(ZipEntry zipEntry, DSSDocument content) {
		if (ASiCUtils.isMimetype(zipEntry.getName())) {
			/*
			 * EN 319 162-1 "A.1 The mimetype file":
			 * "mimetype" shall not be compressed (i.e. compression method in its ZIP header at offset 8 shall be set to zero);
			 */
			if (zipEntry.getMethod() != -1 && ZipEntry.STORED != zipEntry.getMethod()) {
				LOG.warn("'mimetype' shall not be compressed! Compression method in its ZIP header will be set to zero.");
			}
			zipEntry.setMethod(ZipEntry.STORED);
		}
		/*
		 * If you switch to STORED note that you'll have to set the size (or compressed
		 * size; they must be the same, but it's okay to only set one) and CRC yourself
		 * because they must appear before the user data in the resulting zip file.
		 */
		if (ZipEntry.STORED == zipEntry.getMethod()) {
			final byte[] byteArray = DSSUtils.toByteArray(content);
			zipEntry.setSize(byteArray.length);
			zipEntry.setCompressedSize(byteArray.length);
			final CRC32 crc = new CRC32();
			crc.update(byteArray, 0, byteArray.length);
			zipEntry.setCrc(crc.getValue());
		}
		/*
		 * The default is DEFLATED, which will cause the size, compressed size, and CRC
		 * to be set automatically, and the entry's data to be compressed.
		 */
	}

	private void ensureTime(ZipEntry zipEntry, Date creationTime) {
		// if not set, the local current time will be used
		if (creationTime != null) {
			zipEntry.setTime(creationTime.getTime());
		}
	}

	private void resetCounters() {
		byteCounter = 0;
		malformedFilesCounter = 0;
	}

	/**
	 * Returns the next entry from the given ZipInputStream by skipping corrupted or
	 * not accessible files NOTE: returns null only when the end of ZipInputStream
	 * is reached
	 * 
	 * @param zis {@link ZipInputStream} to get next entry from
	 * @return list of file name {@link String}s
	 * @throws DSSException if too many tries failed
	 */
	private ZipEntry getNextValidEntry(ZipInputStream zis) {
		while (malformedFilesCounter < maxMalformedFiles) {
			try {
				return zis.getNextEntry();
			} catch (Exception e) {
				LOG.warn("ZIP container contains a malformed, corrupted or not accessible entry! "
						+ "The entry is skipped. Reason: [{}]", e.getMessage());
				// skip the entry and continue until find the next valid entry or end of the stream
				malformedFilesCounter++;
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
	 * Returns the current file from the given ZipInputStream
	 * 
	 * @param zis           {@link ZipInputStream} of the file
	 * @param containerSize - long byte size of the parent container
	 * @return {@link DSSDocument} created from the given {@code zis}
	 */
	private DSSDocument getCurrentEntryDocument(ZipInputStream zis, ZipEntry entry, long containerSize) {
		long allowedSize = containerSize * maxCompressionRatio;
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			secureCopy(zis, baos, allowedSize);
			baos.flush();

			DSSDocument currentDocument = new InMemoryDocument(baos.toByteArray());
			String fileName = entry.getName();
			currentDocument.setName(entry.getName());
			currentDocument.setMimeType(MimeType.fromFileName(fileName));

			return new ContainerEntryDocument(currentDocument, new DSSZipEntry(entry));

		} catch (IOException e) {
			closeEntry(zis);
			throw new DSSException(String.format("Unable to read an entry binaries. Reason : %s", e.getMessage()), e);
		}
	}

	/**
	 * Reads and copies InputStream in a secure way to OutputStream. Detects
	 * "ZipBombing" (large files inside a zip container) depending on the provided
	 * container size
	 * 
	 * @param is          {@link InputStream} of file
	 * @param os          {@link OutputStream} where save file to.
	 * @param allowedSize defines an allowed size of the ZIP container entries, if
	 *                    -1 skips the validation
	 * @throws IOException if an exception occurs
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

	/**
	 * This method allows reading securely InputStream without caching the content
	 *
	 * @param is          {@link InputStream} to read
	 * @param allowedSize the maximum allowed size of the extracted content
	 * @throws IOException if an exception occurs
	 */
	private void secureRead(InputStream is, long allowedSize) throws IOException {
		byte[] data = new byte[2048];
		int nRead;
		while ((nRead = is.read(data)) != -1) {
			byteCounter += nRead;
			assertExtractEntryLengthValid(allowedSize);
		}
	}

	private void assertExtractEntryLengthValid(long allowedSize) {
		if (allowedSize != -1 && byteCounter > threshold && byteCounter > allowedSize) {
			throw new IllegalInputException("Zip Bomb detected in the ZIP container. Validation is interrupted.");
		}
	}

	private void assertCollectionSizeValid(Collection<?> collection) {
		if (collection.size() > maxAllowedFilesAmount) {
			throw new IllegalInputException("Too many files detected. Cannot extract ASiC content from the file.");
		}
	}

}
