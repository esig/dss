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
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNotETSICompliantException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.DocumentValidator;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.scope.SignatureScopeFinder;

/**
 * This class is the base class for ASiC containers.
 * <p/>
 * Mime-type handling: FROM: ETSI TS 102 918 V1.2.1
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
 * <p/>
 * --> The use of two first bytes is not standard conforming.
 * <p/>
 * 5.2.1 Media type identification
 * 1) File extension: ".asics"|".asice" should be used (".scs"|".sce" is allowed for operating systems and/or file systems not
 * allowing more than 3 characters file extensions). In the case where the container content is to be handled
 * manually, the ".zip" extension may be used.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ASiCContainerValidator extends SignedDocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCContainerValidator.class);

	private static final String MIME_TYPE = "mimetype";
	private static final String MIME_TYPE_COMMENT = MIME_TYPE + "=";
	private static final String META_INF_FOLDER = "META-INF/";

	private SignedDocumentValidator subordinatedValidator;

	/**
	 * The list of the signed documents within the container.
	 */
	private final List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();

	/**
	 * The list of the signatures contained within the container.
	 */
	private final List<DSSDocument> signatures = new ArrayList<DSSDocument>();

	/**
	 * This mime-type comes from the container file name: (zip, asic...).
	 */
	private MimeType asicContainerMimeType;

	/**
	 * This mime-type comes from the 'mimetype' file included within the container.
	 */
	private MimeType asicMimeType;

	/**
	 * This mime-type comes from the ZIP comment:<br/>
	 * The comment field in the ZIP header may be used to identify the type of the data object within the container.
	 * If this field is present, it should be set with "mimetype=" followed by the mime type of the data object held in
	 * the signed data object.
	 */
	protected MimeType asicCommentMimeType;

	/**
	 * This mime-type comes from the "magic number".
	 */
	private MimeType magicNumberMimeType;

	private boolean cadesSigned = false;
	private boolean xadesSigned = false;
	private boolean timestamped = false;

	/**
	 * This method creates a dedicated {@code SignedDocumentValidator} based on the given container type: XAdES or CAdES.
	 *
	 * @param asicContainer The instance of {@code DSSDocument} to validate
	 * @param preamble      contains the beginning of the file
	 * @return {@code SignedDocumentValidator}
	 * @throws DSSException
	 */
	public static SignedDocumentValidator getInstanceForAsics(final DSSDocument asicContainer, final byte[] preamble) throws DSSException {

		ZipInputStream asicsInputStream = null;
		try {

			final ASiCContainerValidator asicContainerValidator = new ASiCContainerValidator();

			asicsInputStream = new ZipInputStream(asicContainer.openStream()); // The underlying stream is closed by the parent (asicsInputStream).

			for (ZipEntry entry = asicsInputStream.getNextEntry(); entry != null; entry = asicsInputStream.getNextEntry()) {

				final String entryName = entry.getName();
				asicContainerValidator.analyseEntries(asicsInputStream, entryName);
			}

			final MimeType asicCommentString = getZipComment(asicContainer.getBytes());
			asicContainerValidator.setAsicCommentMimeType(asicCommentString);

			final MimeType magicNumberMimeType = getMagicNumberMimeType(preamble);
			asicContainerValidator.setMagicNumberMimeType(magicNumberMimeType);

			asicContainerValidator.setAsicContainerMimeType(asicContainer.getMimeType());

			// ASiC-S:
			// - throw new DSSException("ASiC-S profile support only one data file");
			// - DSSNotETSICompliantException.MSG.MORE_THAN_ONE_SIGNATURE

			asicContainerValidator.createSubordinatedContainerValidators();
			return asicContainerValidator;
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
	 * @return
	 */
	@Override
	public SignedDocumentValidator getSubordinatedValidator() {
		return subordinatedValidator;
	}

	private void createSubordinatedContainerValidators() {

		SignedDocumentValidator previousValidator = null;
		for (final DSSDocument signature : signatures) {

			final SignedDocumentValidator currentSubordinatedValidator;
			if (xadesSigned) {
				currentSubordinatedValidator = new ASiCXMLDocumentValidator(signature, detachedContents);
			} else if (cadesSigned) {
				currentSubordinatedValidator = new ASiCCMSDocumentValidator(signature, detachedContents);
			} else if (timestamped) {
				currentSubordinatedValidator = new ASiCTimestampDocumentValidator(signature, detachedContents);
			} else {
				throw new DSSException("The format of the signature is unknown! It is neither XAdES nor CAdES, nor timestamp signature!");
			}
			if (previousValidator != null) {
				previousValidator.setNextValidator(currentSubordinatedValidator);
			} else {
				subordinatedValidator = currentSubordinatedValidator;
			}
			previousValidator = currentSubordinatedValidator;
		}
	}

	private void analyseEntries(final ZipInputStream asicsInputStream, final String entryName) throws DSSException {

		if (isCAdES(entryName)) {

			if (xadesSigned) {
				throw new DSSNotETSICompliantException(DSSNotETSICompliantException.MSG.DIFFERENT_SIGNATURE_FORMATS);
			}
			getEntryElement(entryName, signatures, asicsInputStream);
			cadesSigned = true;
		} else if (isXAdES(entryName)) {

			if (cadesSigned) {
				throw new DSSNotETSICompliantException(DSSNotETSICompliantException.MSG.DIFFERENT_SIGNATURE_FORMATS);
			}
			getEntryElement(entryName, signatures, asicsInputStream);
			xadesSigned = true;
		} else if (isTimestamp(entryName)) {

			getEntryElement(entryName, signatures, asicsInputStream);
			timestamped = true;
		} else if (isASiCManifest(entryName)) {

			getEntryElement(entryName, detachedContents, asicsInputStream);
		} else if (isManifest(entryName)) {

			getEntryElement(entryName, detachedContents, asicsInputStream);
		} else if (isContainer(entryName)) {

			getEntryElement(entryName, detachedContents, asicsInputStream);
		} else if (isMetadata(entryName)) {

			getEntryElement(entryName, detachedContents, asicsInputStream);
		} else if (MIME_TYPE.equalsIgnoreCase(entryName)) {

			asicMimeType = getMimeType(asicsInputStream);
		} else if (entryName.indexOf("/") == -1) {

			getEntryElement(entryName, detachedContents, asicsInputStream);
		} else {

			System.out.println("unknown entry: " + entryName);
		}
	}

	public MimeType getAsicMimeType() {
		return asicMimeType;
	}

	public void setAsicMimeType(final MimeType asicMimeType) {
		this.asicMimeType = asicMimeType;
	}

	public MimeType getAsicCommentMimeType() {
		return asicCommentMimeType;
	}

	public void setAsicCommentMimeType(final MimeType asicCommentMimeType) {
		this.asicCommentMimeType = asicCommentMimeType;
	}

	public MimeType getMagicNumberMimeType() {
		return magicNumberMimeType;
	}

	public void setMagicNumberMimeType(final MimeType magicNumberMimeType) {
		this.magicNumberMimeType = magicNumberMimeType;
	}

	public MimeType getAsicContainerMimeType() {
		return asicContainerMimeType;
	}

	public void setAsicContainerMimeType(final MimeType asicContainerMimeType) {
		this.asicContainerMimeType = asicContainerMimeType;
	}

	private static MimeType getMimeType(final ZipInputStream asicsInputStream) throws DSSException {

		try {
			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			DSSUtils.copy(asicsInputStream, byteArrayOutputStream);
			final String mimeTypeString = byteArrayOutputStream.toString("UTF-8");
			final MimeType asicMimeType = MimeType.fromCode(mimeTypeString);
			return asicMimeType;
		} catch (UnsupportedEncodingException e) {

			throw new DSSException(e);
		}
	}

	private static void getEntryElement(final String entryName, final List<DSSDocument> signatures, final ZipInputStream asicsInputStream) {

		final ByteArrayOutputStream signature = new ByteArrayOutputStream();
		DSSUtils.copy(asicsInputStream, signature);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(signature.toByteArray(), entryName);
		signatures.add(inMemoryDocument);
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

		final boolean manifest = entryName.equals(META_INF_FOLDER + "metadata.xml");
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

		final boolean manifest = entryName.equals(META_INF_FOLDER + "container.xml");
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

		final boolean manifest = entryName.equals(META_INF_FOLDER + "manifest.xml");
		return manifest;
	}

	private static boolean isASiCManifest(String entryName) {

		final boolean manifest = entryName.endsWith(".xml") && entryName.startsWith(META_INF_FOLDER + "ASiCManifest");
		return manifest;
	}

	private static boolean isTimestamp(String entryName) {

		final boolean timestamp = entryName.endsWith(".tst") && entryName.startsWith(META_INF_FOLDER) && entryName.contains("timestamp");
		return timestamp;
	}

	private static boolean isXAdES(final String entryName) {

		final boolean signature = entryName.endsWith(".xml") && entryName.startsWith(META_INF_FOLDER) && entryName.contains("signature");
		return signature;
	}

	private static boolean isCAdES(final String entryName) {

		final boolean signature = entryName.endsWith(".p7s") && entryName.startsWith(META_INF_FOLDER) && entryName.contains("signature");
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

	@Override
	public Reports validateDocument(final Document validationPolicyDom) {

		Reports reports = null;
		DocumentValidator currentSubordinatedValidator = subordinatedValidator;
		do {

			currentSubordinatedValidator.setProcessExecutor(processExecutor);
			currentSubordinatedValidator.setDetachedContents(detachedContents);
			currentSubordinatedValidator.setCertificateVerifier(certificateVerifier);
			final Reports currentReports = currentSubordinatedValidator.validateDocument(validationPolicyDom);
			if (reports == null) {
				reports = currentReports;
			} else {
				reports.setNextReport(currentReports);
			}
			currentSubordinatedValidator = currentSubordinatedValidator.getNextValidator();
		} while (currentSubordinatedValidator != null);
		return reports;
	}

	@Override
	protected SignatureScopeFinder getSignatureScopeFinder() {
		return null;
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		return null;
	}

	@Override
	public DSSDocument removeSignature(String signatureId) throws DSSException {
		return null;
	}
}
