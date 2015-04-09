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
package eu.europa.esig.dss.asic.validation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import eu.europa.esig.dss.ASiCNamespaces;
import eu.europa.esig.dss.AsicManifestDocument;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSNotETSICompliantException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.asic.signature.ASiCService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.report.Reports;

/**
 * This class is the base class for ASiC containers.
 *
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
 *
 * --> The use of two first bytes is not standard conforming.
 *
 * 5.2.1 Media type identification
 * 1) File extension: ".asics"|".asice" should be used (".scs"|".sce" is allowed for operating systems and/or file systems not
 * allowing more than 3 characters file extensions). In the case where the container content is to be handled
 * manually, the ".zip" extension may be used.
 *
 */
public class ASiCContainerValidator extends SignedDocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCContainerValidator.class);

	private static final String MIME_TYPE = "mimetype";
	private static final String MIME_TYPE_COMMENT = MIME_TYPE + "=";
	private static final String META_INF_FOLDER = "META-INF/";

	private final DSSDocument asicContainer;

	/**
	 * This is the subordinated validator: can be XML or CMS
	 */
	private SignedDocumentValidator subordinatedValidator;

	/**
	 * The list of the signatures contained within the container.
	 */
	private final List<DSSDocument> signatures = new ArrayList<DSSDocument>();

	/**
	 * This list caches the validated signatures.
	 */
	private List<AdvancedSignature> validatedSignatures;

	/**
	 * This mime-type comes from the container file name: (zip, asic...).
	 */
	//	private MimeType asicContainerMimeType;

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
	//	protected MimeType asicCommentMimeType;

	private boolean cadesSigned = false;
	private boolean xadesSigned = false;
	private boolean timestamped = false;

	/**
	 * Default constructor used with reflexion (see SignedDocumentValidator)
	 */
	private ASiCContainerValidator() {
		super(null);
		this.asicContainer = null;
	}
	
	public ASiCContainerValidator(final DSSDocument asicContainer) {
		super(null);
		this.asicContainer = asicContainer;
		analyseEntries();

		// ASiC-S:
		// - throw new DSSException("ASiC-S profile support only one data file");
		// - DSSNotETSICompliantException.MSG.MORE_THAN_ONE_SIGNATURE

		createSubordinatedContainerValidators();
	}
	
	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		int headerLength = 500;
		byte[] preamble = new byte[headerLength];
		DSSUtils.readToArray(dssDocument, headerLength, preamble);
		if ((preamble[0] == 'P') && (preamble[1] == 'K')) {
			return true;
		}
		return false;
	}

	private MimeType determinateAsicMimeType(final MimeType asicContainerMimetype, final MimeType asicEntryMimetype) {

		if (isASiCMimeType(asicContainerMimetype)) {

			return asicContainerMimetype;
		}
		if (isASiCMimeType(asicEntryMimetype)) {

			return asicEntryMimetype;
		}
		final MimeType asicCommentString = getZipComment(asicContainer.getBytes());
		if (isASiCMimeType(asicCommentString)) {

			return asicCommentString;
		}
		return null;
	}

	private static boolean isASiCMimeType(final MimeType asicMimeType) {
		return MimeType.ASICS.equals(asicMimeType) || MimeType.ASICE.equals(asicMimeType);
	}

	private AsicManifestDocument getRelatedAsicManifest(final DSSDocument signature) {

		for (final DSSDocument detachedContent : detachedContents) {

			if (!(detachedContent instanceof AsicManifestDocument)) {

				continue;
			}
			final AsicManifestDocument asicManifestDocument = (AsicManifestDocument) detachedContent;
			final String signatureUri = asicManifestDocument.getSignatureUri();
			if (signatureUri.equals(signature.getName())) {

				return asicManifestDocument;
			}
		}
		return null;
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
		if (subordinatedValidator == null) {
			throw new DSSException("This is not an ASiC container. The signature cannot be found!");
		}
	}

	private void analyseEntries() throws DSSException {

		ZipInputStream asicsInputStream = null;
		try {

			MimeType asicEntryMimeType = null;
			asicsInputStream = new ZipInputStream(asicContainer.openStream()); // The underlying stream is closed by the parent (asicsInputStream).

			for (ZipEntry entry = asicsInputStream.getNextEntry(); entry != null; entry = asicsInputStream.getNextEntry()) {

				String entryName = entry.getName();
				if (isCAdES(entryName)) {

					if (xadesSigned) {
						throw new DSSNotETSICompliantException(DSSNotETSICompliantException.MSG.DIFFERENT_SIGNATURE_FORMATS);
					}
					addEntryElement(entryName, signatures, asicsInputStream);
					cadesSigned = true;
				} else if (isXAdES(entryName)) {

					if (cadesSigned) {
						throw new DSSNotETSICompliantException(DSSNotETSICompliantException.MSG.DIFFERENT_SIGNATURE_FORMATS);
					}
					addEntryElement(entryName, signatures, asicsInputStream);
					xadesSigned = true;
				} else if (isTimestamp(entryName)) {

					addEntryElement(entryName, signatures, asicsInputStream);
					timestamped = true;
				} else if (isASiCManifest(entryName)) {

					addAsicManifestEntryElement(entryName, detachedContents, asicsInputStream);
				} else if (isManifest(entryName)) {

					addEntryElement(entryName, detachedContents, asicsInputStream);
				} else if (isContainer(entryName)) {

					addEntryElement(entryName, detachedContents, asicsInputStream);
				} else if (isMetadata(entryName)) {

					addEntryElement(entryName, detachedContents, asicsInputStream);
				} else if (isMimetype(entryName)) {

					final DSSDocument mimeType = addEntryElement(entryName, detachedContents, asicsInputStream);
					asicEntryMimeType = getMimeType(mimeType);
				} else if (entryName.indexOf("/") == -1) {

					addEntryElement(entryName, detachedContents, asicsInputStream);
				} else if (entryName.endsWith("/")) { // Folder
					continue;
				} else {

					addEntryElement(entryName, detachedContents, asicsInputStream);
				}
			}
			asicMimeType = determinateAsicMimeType(asicContainer.getMimeType(), asicEntryMimeType);
			if (MimeType.ASICS == asicMimeType) {

				final ListIterator<DSSDocument> dssDocumentListIterator = detachedContents.listIterator();
				while (dssDocumentListIterator.hasNext()) {

					final DSSDocument dssDocument = dssDocumentListIterator.next();
					final String detachedContentName = dssDocument.getName();
					if ("mimetype".equals(detachedContentName)) {
						dssDocumentListIterator.remove();
					} else if (detachedContentName.indexOf('/') != -1) {
						dssDocumentListIterator.remove();
					}
				}
			}
		} catch (Exception e) {
			if (e instanceof DSSException) {
				throw (DSSException) e;
			}
			throw new DSSException(e);
		} finally {
			IOUtils.closeQuietly(asicsInputStream);
		}
	}

	public MimeType getAsicMimeType() {
		return asicMimeType;
	}

	public void setAsicMimeType(final MimeType asicMimeType) {
		this.asicMimeType = asicMimeType;
	}

	private static MimeType getMimeType(final DSSDocument mimeType) throws DSSException {

		try {
			final InputStream inputStream = mimeType.openStream();
			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			IOUtils.copy(inputStream, byteArrayOutputStream);
			final String mimeTypeString = byteArrayOutputStream.toString("UTF-8");
			final MimeType asicMimeType = MimeType.fromMimeTypeString(mimeTypeString);
			return asicMimeType;
		} catch(IOException e) {
			throw new DSSException(e);
		}
	}

	private static DSSDocument addEntryElement(final String entryName, final List<DSSDocument> list, final ZipInputStream asicsInputStream) throws IOException {

		final ByteArrayOutputStream signature = new ByteArrayOutputStream();
		IOUtils.copy(asicsInputStream, signature);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(signature.toByteArray(), entryName);
		list.add(inMemoryDocument);
		return inMemoryDocument;
	}

	private static void addAsicManifestEntryElement(final String entryName, final List<DSSDocument> list, final ZipInputStream asicsInputStream) throws IOException {

		final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		IOUtils.copy(asicsInputStream, byteArrayOutputStream);
		final AsicManifestDocument inMemoryDocument = new AsicManifestDocument(byteArrayOutputStream.toByteArray(), entryName);
		list.add(inMemoryDocument);
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

	public static boolean isMimetype(String entryName) {
		return MIME_TYPE.equalsIgnoreCase(entryName);
	}

	public static boolean isTimestamp(String entryName) {

		final boolean timestamp = entryName.endsWith(".tst") && entryName.startsWith(META_INF_FOLDER) && entryName.contains("timestamp");
		return timestamp;
	}

	public static boolean isXAdES(final String entryName) {

		final boolean signature = entryName.endsWith(".xml") && entryName.startsWith(META_INF_FOLDER) && entryName.contains("signature");
		return signature;
	}

	public static boolean isCAdES(final String entryName) {

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
					final MimeType mimeType = MimeType.fromMimeTypeString(asicCommentMimeTypeString);
					return mimeType;
				}
			}
		}
		LOG.warn("ZIP comment NOT found!");
		return null;
	}

	/**
	 * Validates the document and all its signatures. The {@code validationPolicyDom} contains the constraint file. If null or empty the default file is used.
	 *
	 * @param validationPolicy {@code ValidationPolicy}
	 * @return
	 */
	@Override
	public Reports validateDocument(final ValidationPolicy validationPolicy) {

		Reports lastReports = null;
		Reports firstReport = null;
		DocumentValidator currentSubordinatedValidator = subordinatedValidator;
		do {

			currentSubordinatedValidator.setProcessExecutor(processExecutor);
			if (MimeType.ASICE.equals(asicMimeType) && currentSubordinatedValidator instanceof ASiCCMSDocumentValidator) {

				final DSSDocument signature = currentSubordinatedValidator.getDocument();
				final AsicManifestDocument relatedAsicManifest = getRelatedAsicManifest(signature);
				final ArrayList<DSSDocument> relatedAsicManifests = new ArrayList<DSSDocument>();
				relatedAsicManifests.add(relatedAsicManifest);
				currentSubordinatedValidator.setDetachedContents(relatedAsicManifests);
			} else {
				currentSubordinatedValidator.setDetachedContents(detachedContents);
			}
			currentSubordinatedValidator.setCertificateVerifier(certificateVerifier);
			final Reports currentReports = currentSubordinatedValidator.validateDocument(validationPolicy);
			if (lastReports == null) {
				firstReport = currentReports;
			} else {
				lastReports.setNextReport(currentReports);
			}
			lastReports = currentReports;
			currentSubordinatedValidator = currentSubordinatedValidator.getNextValidator();
		} while (currentSubordinatedValidator != null);
		return firstReport;
	}

	/**
	 * This is an experimental implementation for Aho's contribution. It is likely to be changed.
	 *
	 * @return {@code List} of {@code AdvancedSignature} within the container
	 */
	@Override
	public List<AdvancedSignature> getSignatures() {

		if (signatures == null) {
			return null;
		}
		if (validatedSignatures != null) {
			return validatedSignatures;
		}
		validatedSignatures = new ArrayList<AdvancedSignature>();
		DocumentValidator currentSubordinatedValidator = subordinatedValidator;
		do {

			final List<AdvancedSignature> signatures = currentSubordinatedValidator.getSignatures();
			for (final AdvancedSignature signature : signatures) {

				validatedSignatures.add(signature);
			}
			currentSubordinatedValidator = currentSubordinatedValidator.getNextValidator();
		} while (currentSubordinatedValidator != null);
		return validatedSignatures;
	}

	/**
	 * This is an experimental implementation for Aho's contribution. It is likely to be changed. The current implementation does not work with CAdES signatures.
	 *
	 * @param signatureId the id of the signature to be removed.
	 * @return the {@code DSSDocument} with removed given signature
	 * @throws DSSException
	 */
	@Override
	public DSSDocument removeSignature(final String signatureId) throws DSSException {

		if (StringUtils.isBlank(signatureId)) {
			throw new NullPointerException("signatureId");
		}

		for (int i = 0; i < signatures.size(); i++) {

			final DSSDocument signature = signatures.get(i);
			final Document root = DSSXMLUtils.buildDOM(signature);
			final Element signatureEl = (Element) root.getDocumentElement().getFirstChild();
			final String idIdentifier = DSSXMLUtils.getIDIdentifier(signatureEl);
			if (signatureId.equals(idIdentifier)) {

				signatures.remove(i);
				final Document signatureDOM = DSSXMLUtils.createDocument(ASiCNamespaces.ASiC, ASiCService.ASICS_NS);
				for (int j = 0; j < signatures.size(); j++) {

					final Document doc = DSSXMLUtils.buildDOM(signature);
					final Node signatureElement = doc.getDocumentElement().getFirstChild();

					final Element newElement = signatureDOM.getDocumentElement();
					signatureDOM.adoptNode(signatureElement);
					newElement.appendChild(signatureElement);
				}
				return new InMemoryDocument(DSSXMLUtils.serializeNode(signatureDOM));
			}
		}
		throw new DSSException("The signature with the given id was not found!");
	}
}
