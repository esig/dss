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
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.PdfLockAction;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pades.validation.ByteRange;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.RevocationInfoArchival;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfCMSRevision;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.pdf.SigFieldPermissions;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandler;
import eu.europa.esig.dss.signature.resources.InMemoryResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Utils for dealing with PAdES
 */
public final class PAdESUtils {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESUtils.class);

	/** Defines a number of the first page in a document */
	public static final int DEFAULT_FIRST_PAGE = 1;

	/** The default resources handler builder to be used across the code */
	public static final InMemoryResourcesHandlerBuilder DEFAULT_RESOURCES_HANDLER_BUILDER = new InMemoryResourcesHandlerBuilder();

	/** The starting bytes of a PDF document */
	private static final byte[] PDF_PREAMBLE = new byte[]{ '%', 'P', 'D', 'F', '-' };

	/** The string used to end a PDF revision */
	private static final byte[] PDF_EOF_STRING = new byte[] { '%', '%', 'E', 'O', 'F' };

	/**
	 * Empty constructor (singleton)
	 */
	private PAdESUtils() {
	}

	/**
	 * Returns the original signed content for the {@code padesSignature}
	 * 
	 * @param padesSignature {@link PAdESSignature}
	 * @return {@link InMemoryDocument}
	 */
	public static InMemoryDocument getOriginalPDF(final PAdESSignature padesSignature) {
		List<DSSDocument> coveredOriginalFile = padesSignature.getDetachedContents(); // coveredContent
		if (Utils.collectionSize(coveredOriginalFile) == 1) {
			// data before adding the signature value
			DSSDocument dataToBeSigned = coveredOriginalFile.get(0);
			ByteRange signatureByteRange = padesSignature.getPdfRevision().getByteRange();
			DSSDocument firstByteRangePart = DSSUtils.splitDocument(dataToBeSigned,
					signatureByteRange.getFirstPartStart(), signatureByteRange.getFirstPartEnd());
			return retrieveCompletePDFRevision(firstByteRangePart);
		}
		return null;
	}

	/**
	 * Returns the original signed content for the {@code pdfRevision}
	 * 
	 * @param pdfRevision {@link PdfRevision}
	 * @return {@link InMemoryDocument}
	 */
	public static InMemoryDocument getOriginalPDF(final PdfCMSRevision pdfRevision) {
		DSSDocument signedDocument = pdfRevision.getSignedData();
		ByteRange signatureByteRange = pdfRevision.getByteRange();
		return retrievePreviousPDFRevision(signedDocument, signatureByteRange);
	}

	/**
	 * Retrieves the PDF document up to the previous PDF Revision, an empty document if such revision is not found
	 *
	 * @param document {@link DSSDocument} the original document
	 * @param byteRange {@link ByteRange} representing the signed revision, to get the previous covered PDF for
	 * @return {@link InMemoryDocument} the PDF document up to the signed revision
	 */
	public static InMemoryDocument retrievePreviousPDFRevision(DSSDocument document, ByteRange byteRange) {
		DSSDocument firstByteRangePart = DSSUtils.splitDocument(document,
				byteRange.getFirstPartStart(), byteRange.getFirstPartEnd());
		return retrieveCompletePDFRevision(firstByteRangePart);
	}

	/**
	 * Returns the PDF document up to the last complete PDF revision (up to the "%%EOF" string)
	 *
	 * @param firstByteRangePart {@link DSSDocument} the document to get last revision for
	 * @return {@link InMemoryDocument}
	 */
	private static InMemoryDocument retrieveCompletePDFRevision(DSSDocument firstByteRangePart) {
		ByteArrayOutputStream tempLine = null;
		ByteArrayOutputStream tempRevision = null;
		try (InputStream is = firstByteRangePart.openStream();
				BufferedInputStream bis = new BufferedInputStream(is);
			 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

			tempLine = new ByteArrayOutputStream();
			tempRevision = new ByteArrayOutputStream();
			int b;
			while ((b = bis.read()) != -1) {

				tempLine.write(b);
				byte[] stringBytes = tempLine.toByteArray();

				if (Arrays.equals(PDF_EOF_STRING, stringBytes)) {
					tempLine.close();
					tempLine = new ByteArrayOutputStream();

					tempRevision.write(stringBytes);
					int c = bis.read();
					// if \n
					if (c == DSSUtils.LINE_FEED) {
						tempRevision.write(c);
					}
					// if \r
					else if (c == DSSUtils.CARRIAGE_RETURN) {
						int d = bis.read();
						// if \r\n
						if (d == DSSUtils.LINE_FEED) {
							tempRevision.write(c);
							tempRevision.write(d);
						} else {
							tempLine.write(c);
							tempLine.write(d);
						}
					} else {
						tempLine.write(c);
					}
					baos.write(tempRevision.toByteArray());
					tempRevision.close();
					tempRevision = new ByteArrayOutputStream();

				} else if (DSSUtils.isLineBreakByte((byte) b) || stringBytes.length > PDF_EOF_STRING.length) {
					tempRevision.write(tempLine.toByteArray());
					tempLine.close();
					tempLine = new ByteArrayOutputStream();
				}

			}

			baos.flush();
			return new InMemoryDocument(baos.toByteArray(), "original.pdf", MimeType.PDF);

		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the last revision", e);

		} finally {
			if (tempLine != null) {
				Utils.closeQuietly(tempLine);
			}
			if (tempRevision != null) {
				Utils.closeQuietly(tempRevision);
			}
		}
	}

	/**
	 * Returns the revision content according to the provided byteRange ([0]-[3])
	 *
	 * @param dssDocument {@link DSSDocument} to extract the content from
	 * @param byteRange {@link ByteRange} indicating the revision boundaries
	 * @return revision binaries
	 * @throws IOException in case if an exception occurs
	 */
	public static byte[] getRevisionContent(DSSDocument dssDocument, ByteRange byteRange) throws IOException {
		int beginning = byteRange.getFirstPartStart();
		int endSigValueContent = byteRange.getSecondPartStart();
		int endValue = byteRange.getSecondPartEnd();

		byte[] revisionByteArray = new byte[endSigValueContent + endValue - beginning];

		try (InputStream is = dssDocument.openStream()) {

			DSSUtils.skipAvailableBytes(is, beginning);
			DSSUtils.readAvailableBytes(is, revisionByteArray, 0, endSigValueContent + endValue - beginning);

		} catch (IllegalStateException e) {
			LOG.error("Cannot extract revision binaries. Reason : {}", e.getMessage());
		}

		return revisionByteArray;
	}

	/**
	 * Returns a signed content according to the provided byteRange ([0]-[1] and [2]-[3]) from the extracted revision
	 *
	 * @param revisionBinaries a byte array representing an extracted revision content
	 * @param byteRange {@link ByteRange} indicating which content range should be extracted
	 * @return extracted signed data
	 * @throws IOException in case if an exception occurs
	 */
	public static byte[] getSignedContentFromRevision(byte[] revisionBinaries, ByteRange byteRange) throws IOException {
		// Adobe Digital Signatures in a PDF (p5): In Figure 4, the hash is calculated
		// for bytes 0 through 840, and 960 through 1200. [0, 840, 960, 1200]
		int beginning = byteRange.getFirstPartStart();
		int startSigValueContent = byteRange.getFirstPartEnd();
		int endSigValueContent = byteRange.getSecondPartStart();
		int endValue = byteRange.getSecondPartEnd();

		byte[] signedDataByteArray = new byte[startSigValueContent + endValue];

		try (InputStream is = new ByteArrayInputStream(revisionBinaries)) {

			// do not skip the beginning, because the revision already has the binaries in the byte range
			DSSUtils.readAvailableBytes(is, signedDataByteArray, 0, startSigValueContent - beginning);
			DSSUtils.skipAvailableBytes(is, endSigValueContent - startSigValueContent - beginning);
			DSSUtils.readAvailableBytes(is, signedDataByteArray, startSigValueContent - beginning, endValue);

		} catch (IllegalStateException e) {
			LOG.error("Cannot extract revision binaries. Reason : {}", e.getMessage());
		}

		return signedDataByteArray;
	}

	/**
	 * Returns {@link RevocationInfoArchival} from the given encodable
	 * 
	 * @param encodable the encoded data to be parsed
	 * @return an instance of RevocationValues or null if the parsing failed
	 */
	public static RevocationInfoArchival getRevocationInfoArchival(ASN1Encodable encodable) {
		if (encodable != null) {
			try {
				return RevocationInfoArchival.getInstance(encodable);
			} catch (Exception e) {
				LOG.warn("Unable to parse RevocationInfoArchival", e);
			}
		}
		return null;
	}

	/**
	 * Checks if the given {@code DSSDocument} represents a PDF document
	 *
	 * @param document {@link DSSDocument} to check
	 * @return TRUE if the document is a PDF, FALSE otherwise
	 */
	public static boolean isPDFDocument(DSSDocument document) {
		return DSSUtils.startsWithBytes(document, PDF_PREAMBLE);
	}

	/**
	 * This method extracts {@code SigFieldPermissions} (for instance /Lock dictionary) from a wrapping dictionary
	 *
	 * @param wrapper {@link PdfDict} wrapping the dictionary having permissions
	 * @return {@link SigFieldPermissions}
	 */
	public static SigFieldPermissions extractPermissionsDictionary(PdfDict wrapper) {
		final SigFieldPermissions sigFieldPermissions = new SigFieldPermissions();

		String action = wrapper.getNameValue(PAdESConstants.ACTION_NAME);
		sigFieldPermissions.setAction(PdfLockAction.forName(action));

		List<String> fields = new ArrayList<>();
		PdfArray fieldsArray = wrapper.getAsArray(PAdESConstants.FIELDS_NAME);
		if (fieldsArray != null) {
			for (int j = 0; j < fieldsArray.size(); j++) {
				String field = fieldsArray.getString(j);
				if (field != null) {
					fields.add(field);
				}
			}
		}
		sigFieldPermissions.setFields(fields);

		if (PAdESConstants.SIG_FIELD_LOCK_NAME.equals(wrapper.getNameValue(PAdESConstants.TYPE_NAME))) {
			Number permissions = wrapper.getNumberValue(PAdESConstants.PERMISSIONS_NAME);
			if (permissions != null) {
				CertificationPermission certificationPermission = CertificationPermission.fromCode(permissions.intValue());
				sigFieldPermissions.setCertificationPermission(certificationPermission);
			}
		}

		return sigFieldPermissions;
	}

	/**
	 * Returns a list of VRI dictionaries, corresponding to the given signature (VRI) SHA-1 name
	 *
	 * NOTE: {@code vriName} can be null. In this case all /VRI dictionaries are returned
	 *
	 * @param pdfDssDict {@link PdfDssDict} to extract /VRI dictionaries from
	 * @param vriName {@link String} name of the /VRI dictionary to retrieve (optional)
	 * @return list of {@link PdfVRIDict}s
	 */
	public static List<PdfVRIDict> getVRIsWithName(PdfDssDict pdfDssDict, String vriName) {
		List<PdfVRIDict> vris = pdfDssDict.getVRIs();
		if (Utils.isCollectionEmpty(vris)) {
			return Collections.emptyList();
		}
		if (vriName == null) {
			return vris;
		}
		for (PdfVRIDict vriDict : vris) {
			if (vriName.equals(vriDict.getName())) {
				return Collections.singletonList(vriDict);
			}
		}
		return Collections.emptyList();
	}

	/**
	 * This method initializes a new {@code DSSResourcesHandler} object
	 *
	 * @return {@link DSSResourcesHandler}
	 */
	public static DSSResourcesHandler initializeDSSResourcesHandler() {
		return DEFAULT_RESOURCES_HANDLER_BUILDER.createResourcesHandler();
	}

}
