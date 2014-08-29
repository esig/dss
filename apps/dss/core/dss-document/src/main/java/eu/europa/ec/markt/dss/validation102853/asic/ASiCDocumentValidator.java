/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.asic;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNotETSICompliantException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;

/**
 * This class is the base class for ASiC containers.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public abstract class ASiCDocumentValidator extends SignedDocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCDocumentValidator.class);

	public static final String MIME_TYPE = "mimetype";
	public static final String MIME_TYPE_COMMENT = MIME_TYPE + "=";

	/**
	 * This class represents one signed document which is the composed of: data stream and the file name.
	 */
	private static class SignedDocument {

		ByteArrayOutputStream byteArrayOutputStream = null;
		String dataFileName = null;

		private SignedDocument(final ByteArrayOutputStream byteArrayOutputStream, final String dataFileName) {

			this.byteArrayOutputStream = byteArrayOutputStream;
			this.dataFileName = dataFileName;
		}
	}

	/**
	 * It can also be possible to read the mimetype from the binary file:
	 * FROM: ETSI TS 102 918 V1.2.1
	 * A.1 Mimetype
	 * The "mimetype" object, when stored in a ZIP, file can be used to support operating systems that rely on some content in
	 * specific positions in a file (the so called "magic number" as described in RFC 4288 [11] in order to select the specific
	 * application that can load and elaborate the file content. The following restrictions apply to the mimetype to support this
	 * feature:
	 * • it has to be the first in the archive;
	 * • it cannot contain "Extra fields" (i.e. extra field length at offset 28 shall be zero);
	 * • it cannot be compressed (i.e. compression method at offset 8 shall be zero);
	 * • the first 4 octets shall have the hex values: "50 4B 03 04".
	 * An application can ascertain if this feature is used by checking if the string "mimetype" is found starting at offset 30. In
	 * this case it can be assumed that a string representing the container mime type is present starting at offset 38; the length
	 * of this string is contained in the 4 octets starting at offset 18.
	 * All multi-octets values are little-endian.
	 * The "mimetype" shall NOT be compressed or encrypted inside the ZIP file.

	 * --> The use of two first bytes is not standard conforming.
	 *
	 * 5.2.1 Media type identification
	 * 1) File extension: ".asics"|".asice" should be used (".scs"|".sce" is allowed for operating systems and/or file systems not
	 * allowing more than 3 characters file extensions). In the case where the container content is to be handled
	 * manually, the ".zip" extension may be used.

	 * @param asicContainer The instance of {@code DSSDocument} to validate
	 * @param preamble      contains the beginning of the file
	 * @return
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	public static SignedDocumentValidator getInstanceForAsics(final DSSDocument asicContainer, byte[] preamble) throws DSSException {

		ZipInputStream asicsInputStream = null;
		try {

			asicsInputStream = new ZipInputStream(asicContainer.openStream()); // The underlying stream is closed by the parent (asicsInputStream).

			List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
			List<DSSDocument> signatures = new ArrayList<DSSDocument>();
			ZipEntry entry;

			boolean cadesSigned = false;
			boolean xadesSigned = false;
			boolean timestamped = false;

			MimeType asicMimeType = null;

			while ((entry = asicsInputStream.getNextEntry()) != null) {

				final String entryName = entry.getName();
				if (isCAdES(entryName)) {

					if (xadesSigned) {
						throw new DSSNotETSICompliantException(DSSNotETSICompliantException.MSG.DIFFERENT_SIGNATURE_FORMATS);
					}
					final ByteArrayOutputStream signature = new ByteArrayOutputStream();
					DSSUtils.copy(asicsInputStream, signature);
					final InMemoryDocument inMemoryDocument = new InMemoryDocument(signature.toByteArray(), entryName);
					signatures.add(inMemoryDocument);
					cadesSigned = true;
				} else if (isXAdES(entryName)) {

					if (cadesSigned) {
						throw new DSSNotETSICompliantException(DSSNotETSICompliantException.MSG.DIFFERENT_SIGNATURE_FORMATS);
					}
					final ByteArrayOutputStream signature = new ByteArrayOutputStream();
					DSSUtils.copy(asicsInputStream, signature);
					final InMemoryDocument inMemoryDocument = new InMemoryDocument(signature.toByteArray(), entryName);
					signatures.add(inMemoryDocument);
					xadesSigned = true;
				} else if (isTimestamp(entryName)) {

					final ByteArrayOutputStream timestamp = new ByteArrayOutputStream();
					DSSUtils.copy(asicsInputStream, timestamp);
					final InMemoryDocument inMemoryDocument = new InMemoryDocument(timestamp.toByteArray(), entryName);
					signatures.add(inMemoryDocument);
					timestamped = true;
				} else if (isASiCManifest(entryName)) {

					final ByteArrayOutputStream manifest = new ByteArrayOutputStream();
					DSSUtils.copy(asicsInputStream, manifest);
					final InMemoryDocument inMemoryDocument = new InMemoryDocument(manifest.toByteArray(), entryName);
					// TODO (22/08/2014): For the moment the manifest file is added to the signatures: to be updated
					signatures.add(inMemoryDocument);
				} else if (isManifest(entryName)) {

					final ByteArrayOutputStream manifest = new ByteArrayOutputStream();
					DSSUtils.copy(asicsInputStream, manifest);
					final InMemoryDocument inMemoryDocument = new InMemoryDocument(manifest.toByteArray(), entryName);
					// TODO (22/08/2014): For the moment the manifest file is added to the signatures: to be updated
					signatures.add(inMemoryDocument);
				} else if (isContainer(entryName)) {

					final ByteArrayOutputStream manifest = new ByteArrayOutputStream();
					DSSUtils.copy(asicsInputStream, manifest);
					final InMemoryDocument inMemoryDocument = new InMemoryDocument(manifest.toByteArray(), entryName);
					// TODO (22/08/2014): For the moment the manifest file is added to the signatures: to be updated
					signatures.add(inMemoryDocument);
				} else if (isMetadata(entryName)) {

					final ByteArrayOutputStream manifest = new ByteArrayOutputStream();
					DSSUtils.copy(asicsInputStream, manifest);
					final InMemoryDocument inMemoryDocument = new InMemoryDocument(manifest.toByteArray(), entryName);
					// TODO (22/08/2014): For the moment the manifest file is added to the signatures: to be updated
					signatures.add(inMemoryDocument);
				} else if (entryName.equalsIgnoreCase(MIME_TYPE)) {

					ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
					DSSUtils.copy(asicsInputStream, byteArrayOutputStream);
					final String mimeTypeString = byteArrayOutputStream.toString("UTF-8");
					asicMimeType = MimeType.fromCode(mimeTypeString);
				} else if (entryName.indexOf("/") == -1) {

					final ByteArrayOutputStream signedDocument = new ByteArrayOutputStream();
					DSSUtils.copy(asicsInputStream, signedDocument);
					final InMemoryDocument inMemoryDocument = new InMemoryDocument(signedDocument.toByteArray(), entryName);
					detachedContents.add(inMemoryDocument);
				}
			}

			final MimeType asicCommentString = getZipComment(asicContainer.getBytes());
			final MimeType magicNumberMimeType = getMagicNumberMimeType(preamble);

			// ASiC-S:
			// - throw new DSSException("ASiC-S profile support only one data file");
			// - DSSNotETSICompliantException.MSG.MORE_THAN_ONE_SIGNATURE

			if (xadesSigned) {

				ASiCXMLDocumentValidator xmlValidator = null;
				for (final DSSDocument signature : signatures) {

					xmlValidator = new ASiCXMLDocumentValidator(signature, detachedContents);
					xmlValidator.setAsicContainerMimeType(asicContainer.getMimeType());
					xmlValidator.setAsicMimeType(asicMimeType);
					xmlValidator.setAsicCommentMimeType(asicCommentString);
					xmlValidator.setMagicNumberMimeType(magicNumberMimeType);
				}
				return xmlValidator;
			} else if (cadesSigned) {

				ASiCCMSDocumentValidator cmsValidator = null;
				for (final DSSDocument signature : signatures) {

					cmsValidator = new ASiCCMSDocumentValidator(signature, detachedContents);
					cmsValidator.setAsicContainerMimeType(asicContainer.getMimeType());
					cmsValidator.setAsicMimeType(asicMimeType);
					cmsValidator.setAsicCommentMimeType(asicCommentString);
					cmsValidator.setMagicNumberMimeType(magicNumberMimeType);
				}
				return cmsValidator;
			} else if (timestamped) {

				ASiCTimestampDocumentValidator timestampValidator = null;
				for (final DSSDocument signature : signatures) {

					timestampValidator = new ASiCTimestampDocumentValidator(signature, detachedContents);
					timestampValidator.setAsicContainerMimeType(asicContainer.getMimeType());
					timestampValidator.setAsicMimeType(asicMimeType);
					timestampValidator.setAsicCommentMimeType(asicCommentString);
					timestampValidator.setMagicNumberMimeType(magicNumberMimeType);
				}
				return timestampValidator;
			} else {
				throw new DSSException("It is neither XAdES nor CAdES, nor timestamp signature!");
			}
		} catch (Exception e) {
			if (e instanceof DSSException) {
				throw (DSSException) e;
			}
			throw new DSSException(e);
		} finally {
			DSSUtils.closeQuietly(asicsInputStream);
		}
	}

	/**
	 * 6.2.2 Contents of Container
	 * 4) Other application specific information may be added in further files contained within the META-INF directory, such as:
	 * c) "META-INF/metadata.xml" has a user defined content. If present, its content shall be well formed XML conformant to OEBPS Container Format (OCF) [4] specifications.
	 *
	 * @param entryName
	 * @return
	 */
	private static boolean isMetadata(final String entryName) {

		final boolean manifest = entryName.equals("META-INF/metadata.xml");
		return manifest;
	}

	/**
	 * 6.2.2 Contents of Container
	 * 4) Other application specific information may be added in further files contained within the META-INF directory, such as:
	 * a) "META-INF/container.xml" if present shall be well formed XML conformant to OEBPS Container Format (OCF) [4] specifications. It shall identify the MIME type and full path
	 * of all the root data objects in the container, as specified in OCF.
	 *
	 * @param entryName
	 * @return
	 */
	private static boolean isContainer(final String entryName) {

		final boolean manifest = entryName.equals("META-INF/container.xml");
		return manifest;
	}

	/**
	 * 6.2.2 Contents of Container
	 * 4) Other application specific information may be added in further files contained within the META-INF directory, such as:
	 * b) "META-INF/manifest.xml" if present shall be well formed XML conformant to OASIS Open Document Format [6] specifications.
	 * NOTE 4: according to ODF [6] specifications, inclusion of reference to other META-INF information, such as *signatures*.xml, in manifest.xml is optional. In this way it is
	 * possible to protect the container's content signing manifest.xml while allowing to add later signatures.
	 *
	 * @param entryName
	 * @return
	 */
	private static boolean isManifest(final String entryName) {

		final boolean manifest = entryName.equals("META-INF/manifest.xml");
		return manifest;
	}

	private static boolean isASiCManifest(String entryName) {

		final boolean manifest = entryName.endsWith(".xml") && entryName.startsWith("META-INF/ASiCManifest");
		return manifest;
	}

	private static boolean isTimestamp(String entryName) {

		final boolean timestamp = entryName.endsWith(".tst") && entryName.startsWith("META-INF/") && entryName.contains("timestamp");
		return timestamp;
	}

	private static boolean isXAdES(final String entryName) {

		final boolean signature = entryName.endsWith(".xml") && entryName.startsWith("META-INF/") && entryName.contains("signatures");
		return signature;
	}

	private static boolean isCAdES(final String entryName) {

		final boolean signature = entryName.endsWith(".p7s") && entryName.startsWith("META-INF/") && entryName.contains("signature");
		return signature;
	}

	private static MimeType getZipComment(final byte[] buffer) {

		final int len = buffer.length;
		final byte[] magicDirEnd = {0x50, 0x4b, 0x05, 0x06};
		final int buffLen = Math.min(buffer.length, len);
		// Check the buffer from the end
		for (int ii = buffLen - magicDirEnd.length - 22; ii >= 0; ii--) {

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
				int realLen = buffLen - ii - 22;
				if (commentLen != realLen) {
					LOG.warn("WARNING! ZIP comment size mismatch: directory says len is " + commentLen + ", but file ends after " + realLen + " bytes!");
				}
				final String comment = new String(buffer, ii + 22, Math.min(commentLen, realLen));

				final int indexOf = comment.indexOf(MIME_TYPE_COMMENT);
				if (indexOf > -1) {

					final String asicCommentMimeTypeString = comment.substring(MIME_TYPE_COMMENT.length() + indexOf);
					final MimeType mimeType = MimeType.fromCode(asicCommentMimeTypeString);
					return mimeType;
				}
			}
		}
		LOG.warn("ZIP comment NOT found!");
		return null;
	}

	private static MimeType getMagicNumberMimeType(final byte[] preamble) {

		if (preamble[28] == 0 && preamble[8] == 0) {

			final byte[] lengthBytes = Arrays.copyOfRange(preamble, 18, 18 + 4);
			final int length = java.nio.ByteBuffer.wrap(lengthBytes).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();

			final byte[] mimeTypeTagBytes = Arrays.copyOfRange(preamble, 30, 30 + 8);
			final String mimeTypeTagString = DSSUtils.getUtf8String(mimeTypeTagBytes);
			if (MIME_TYPE.equals(mimeTypeTagString)) {

				final byte[] mimeTypeBytes = Arrays.copyOfRange(preamble, 30 + 8, 30 + 8 + length);
				String magicNumberMimeType = DSSUtils.getUtf8String(mimeTypeBytes);
				if (DSSUtils.isNotBlank(magicNumberMimeType)) {

					MimeType mimeType = MimeType.fromCode(magicNumberMimeType);
					return mimeType;
				}
			}
		}
		return null;
	}
}
