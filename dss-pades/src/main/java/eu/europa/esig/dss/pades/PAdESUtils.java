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
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.ByteRange;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PdfByteRangeDocument;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.RevocationInfoArchival;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfArray;
import eu.europa.esig.dss.pdf.PdfCMSRevision;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVriDict;
import eu.europa.esig.dss.pdf.SigFieldPermissions;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandler;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandlerBuilder;
import eu.europa.esig.dss.signature.resources.InMemoryResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Utils for dealing with PAdES
 */
public final class PAdESUtils {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESUtils.class);

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
		// empty
	}

	/**
	 * Returns the original signed content for the {@code padesSignature}
	 * 
	 * @param padesSignature {@link PAdESSignature}
	 * @return {@link DSSDocument}
	 */
	public static DSSDocument getOriginalPDF(final PAdESSignature padesSignature) {
		return getOriginalPDF(padesSignature.getPdfRevision());
	}

	/**
	 * Returns the original signed content for the {@code pdfRevision}
	 * 
	 * @param pdfRevision {@link PdfRevision}
	 * @return {@link DSSDocument}
	 */
	public static DSSDocument getOriginalPDF(final PdfCMSRevision pdfRevision) {
		return pdfRevision.getPreviousRevision();
	}

	/**
	 * Returns the complete revision content according to the provided byteRange ([0]-[3])
	 *
	 * @param dssDocument {@link DSSDocument} to extract the content from
	 * @param byteRange {@link ByteRange} indicating the revision boundaries
	 * @return revision binaries
	 */
	public static DSSDocument getRevisionContent(DSSDocument dssDocument, ByteRange byteRange) {
		int beginning = byteRange.getFirstPartStart();
		int endSigValueContent = byteRange.getSecondPartStart();
		int endValue = byteRange.getSecondPartEnd();

		ByteRange revisionByteRange = getTwoIntegersByteRange(beginning, endSigValueContent + endValue - beginning);
		return new PdfByteRangeDocument(dssDocument, revisionByteRange);
	}

	/**
	 * This method returns the best previous revision from {@code revisions} collection
	 * corresponding to the {@code byteRange}
	 *
	 * @param byteRange {@link ByteRange} of a signature to get previous revision for
	 * @param revisions a collection of {@link PdfByteRangeDocument} revisions
	 * @return {@link DSSDocument} previous revision content if found, empty document otherwise
	 */
	public static DSSDocument getPreviousRevision(ByteRange byteRange,  Collection<PdfByteRangeDocument> revisions) {
		PdfByteRangeDocument bestCandidate = null;
		int firstPartLength = byteRange.getFirstPartStart() + byteRange.getFirstPartEnd();
		for (PdfByteRangeDocument byteRangeDocument : revisions) {
			ByteRange currentByteRange = byteRangeDocument.getByteRange();
			if (firstPartLength > currentByteRange.getLength() &&
					(bestCandidate == null || currentByteRange.getLength() > bestCandidate.getByteRange().getLength())) {
				bestCandidate = byteRangeDocument;
			}
		}
		return bestCandidate != null ? bestCandidate : InMemoryDocument.createEmptyDocument();
	}

	/**
	 * Gets the SignatureValue from the {@code dssDocument} according to the {@code byteRange}
	 *
	 * Example: extracts bytes from 841 to 959. [0, 840, 960, 1200]
	 *
	 * @param dssDocument {@link DSSDocument} to process
	 * @param byteRange {@link ByteRange} specifying the signatureValue
	 * @return signatureValue binaries
	 */
	public static byte[] getSignatureValue(DSSDocument dssDocument, ByteRange byteRange) {
		int startSigValueContent = byteRange.getFirstPartStart() + byteRange.getFirstPartEnd() + 1;
		int endSigValueContent = byteRange.getSecondPartStart() - 1;

		final PdfByteRangeDocument sigValueDocument = new PdfByteRangeDocument(
				dssDocument, getTwoIntegersByteRange(startSigValueContent, endSigValueContent));
		return Utils.fromHex(new String(DSSUtils.toByteArray(sigValueDocument)));
	}

	/**
	 * This method replaces /Contents field value with a given {@code cmsSignedData} binaries
	 *
	 * @param toBeSignedDocument {@link DSSDocument} representing a document to be signed with an empty signature value
	 *                                              (Ex.: {@code /Contents <00000 ... 000000>})
	 * @param cmsSignedData byte array representing DER-encoded CMS Signed Data
	 * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}. Optional.
	 *                                If non is provided, a default {@code InMemoryResourcesHandlerBuilder} will be used.
	 * @return {@link DSSDocument} PDF document containing the inserted CMS signature
	 */
	public static DSSDocument replaceSignature(final DSSDocument toBeSignedDocument, final byte[] cmsSignedData,
											   DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
		Objects.requireNonNull(toBeSignedDocument, "toBeSignedDocument cannot be null!");
		Objects.requireNonNull(cmsSignedData, "cmsSignedData cannot be null!");
		if (resourcesHandlerBuilder == null) {
			resourcesHandlerBuilder = DEFAULT_RESOURCES_HANDLER_BUILDER;
		}

		if (Utils.isArrayEmpty(cmsSignedData)) {
			throw new IllegalArgumentException("cmsSignedData cannot be empty!");
		}
		byte[] signature = Utils.toHex(cmsSignedData).getBytes();

		ByteArrayOutputStream temp = null;
		try (DSSResourcesHandler resourcesHandler = resourcesHandlerBuilder.createResourcesHandler();
			 OutputStream os = resourcesHandler.createOutputStream();
			 InputStream is = toBeSignedDocument.openStream();
			 BufferedInputStream bis = new BufferedInputStream(is)) {

			final byte startSuspicion = '<';
			final byte continueSuspicion = '0';

			boolean suspicion = false;
			boolean cmsPasted = false;

			int b;
			while ((b = bis.read()) != -1) {

				if (suspicion) {
					if (continueSuspicion == b) {
						temp.write(b);
						if (signature.length == temp.size()) {
							if (cmsPasted) {
								throw new IllegalInputException("PDF document contains more than one empty signature!");
							}
							os.write(signature);
							temp.close();
							suspicion = false;
							cmsPasted = true;
						}
						continue;

					} else {
						os.write(temp.toByteArray());
						temp.close();
						suspicion = false;
					}
				}

				os.write(b);

				if (startSuspicion == b) {
					temp = new ByteArrayOutputStream();
					suspicion = true;
				}

			}

			if (!cmsPasted) {
				throw new IllegalInputException("Reserved space to insert a signature was not found!");
			}

			return resourcesHandler.writeToDSSDocument();

		} catch (IOException e) {
			throw new DSSException(String.format(
					"Unable to replace /Contents value within a toBeSigned document. Reason : %s", e.getMessage()), e);

		} finally {
			if (temp != null) {
				Utils.closeQuietly(temp);
			}
		}
	}

	/**
	 * Parses {@code document} and extracts all revisions based on {@code %%EOF} string
	 *
	 * @param document {@link DSSDocument} PDF document to extract revisions from
	 * @return a list of {@link PdfByteRangeDocument}s representing extracted revisions
	 */
	public static List<PdfByteRangeDocument> extractRevisions(DSSDocument document) {
		final List<PdfByteRangeDocument> revisions = new ArrayList<>();

		int position = 0;
		ByteArrayOutputStream tempLine = null;
		try (InputStream is = document.openStream();
			 BufferedInputStream bis = new BufferedInputStream(is)) {
			tempLine = new ByteArrayOutputStream();
			int b;
			while ((b = bis.read()) != -1) {
				++position;

				tempLine.write(b);
				byte[] stringBytes = tempLine.toByteArray();

				if (Arrays.equals(PDF_EOF_STRING, stringBytes)) {
					tempLine.close();
					tempLine = new ByteArrayOutputStream();

					int eofPosition = position;
					int c = bis.read();
					if (c != -1) {
						++position;
					}

					if (DSSUtils.LINE_FEED == c) {
						// if \n
						++eofPosition;
					} else if (DSSUtils.CARRIAGE_RETURN == c) {
						// if \r
						++eofPosition;

						int d = bis.read();
						if (d != -1) {
							++position;
						}
						if (DSSUtils.LINE_FEED == d) {
							// if \r\n
							++eofPosition;
						}
					}

					revisions.add(new PdfByteRangeDocument(document, getTwoIntegersByteRange(0, eofPosition)));

				} else if (DSSUtils.isLineBreakByte((byte) b) || stringBytes.length > PDF_EOF_STRING.length) {
					tempLine.close();
					tempLine = new ByteArrayOutputStream();
				}

			}

			return revisions;

		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the last revision", e);

		} finally {
			if (tempLine != null) {
				Utils.closeQuietly(tempLine);
			}
		}
	}

	private static ByteRange getTwoIntegersByteRange(int offset, int position) {
		return new ByteRange(new int[] { offset, position - offset, position, 0 });
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
	 * @return list of {@link PdfVriDict}s
	 */
	public static List<PdfVriDict> getVRIsWithName(PdfDssDict pdfDssDict, String vriName) {
		List<PdfVriDict> vris = pdfDssDict.getVRIs();
		if (Utils.isCollectionEmpty(vris)) {
			return Collections.emptyList();
		}
		if (vriName == null) {
			return vris;
		}
		for (PdfVriDict vriDict : vris) {
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
