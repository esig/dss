/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.PdfLockAction;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
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
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandler;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import eu.europa.esig.dss.signature.resources.InMemoryResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	// TODO : replace with CAdESUtils.DEFAULT_RESOURCES_HANDLER_BUILDER ?
	/** The default resources handler builder to be used across the code */
	public static final InMemoryResourcesHandlerBuilder DEFAULT_RESOURCES_HANDLER_BUILDER = new InMemoryResourcesHandlerBuilder();

	/** The default PDF memory usage setting to be used on a PDF document reading */
	public static final PdfMemoryUsageSetting DEFAULT_PDF_MEMORY_USAGE_SETTING = PdfMemoryUsageSetting.memoryFull();

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
		Objects.requireNonNull(dssDocument, "DSSDocument cannot be null!");
		Objects.requireNonNull(byteRange, "ByteRange cannot be null!");
		assertPdfDocument(dssDocument);

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
	public static DSSDocument getPreviousRevision(ByteRange byteRange, Collection<PdfByteRangeDocument> revisions) {
		Objects.requireNonNull(byteRange, "ByteRange cannot be null!");
		Objects.requireNonNull(revisions, "Revisions cannot be null!");

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
		Objects.requireNonNull(dssDocument, "DSSDocument cannot be null!");
		Objects.requireNonNull(byteRange, "ByteRange cannot be null!");
		assertPdfDocument(dssDocument);

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
		Objects.requireNonNull(toBeSignedDocument, "DSSDocument cannot be null!");
		Objects.requireNonNull(cmsSignedData, "cmsSignedData cannot be null!");
		assertPdfDocument(toBeSignedDocument);

		if (resourcesHandlerBuilder == null) {
			resourcesHandlerBuilder = DEFAULT_RESOURCES_HANDLER_BUILDER;
		}

		if (Utils.isArrayEmpty(cmsSignedData)) {
			throw new IllegalArgumentException("cmsSignedData cannot be empty!");
		}
		byte[] signature = Utils.toHex(cmsSignedData).getBytes();

		try (DSSResourcesHandler resourcesHandler = resourcesHandlerBuilder.createResourcesHandler();
			 OutputStream os = resourcesHandler.createOutputStream();
			 InputStream is = toBeSignedDocument.openStream()) {

			final byte startSuspicion = '<';
			final byte continueSuspicion = '0';

			boolean suspicion = false;
			boolean cmsPasted = false;
			int zeros = 0;

			// NOTE: read by blocks, as per-byte read/write calls are costly on large documents
			final byte[] buffer = new byte[8192];
			int count;
			while ((count = is.read(buffer)) != -1) {
				int from = 0;
				for (int i = 0; i < count; i++) {
					byte b = buffer[i];

					if (suspicion) {
						if (continueSuspicion == b) {
							from = i + 1;
							if (signature.length == ++zeros) {
								if (cmsPasted) {
									throw new IllegalInputException("PDF document contains more than one empty signature!");
								}
								os.write(signature);
								suspicion = false;
								cmsPasted = true;
							}
							continue;

						} else {
							if (zeros > 0) {
								byte[] temp = new byte[zeros];
								Arrays.fill(temp, continueSuspicion);
								os.write(temp);
							}
							suspicion = false;
						}
					}

					if (startSuspicion == b) {
						os.write(buffer, from, i + 1 - from);
						from = i + 1;
						zeros = 0;
						suspicion = true;
					}
				}
				os.write(buffer, from, count - from);
			}

			if (!cmsPasted) {
				throw new IllegalInputException("Reserved space to insert a signature was not found!");
			}

			return resourcesHandler.writeToDSSDocument();

		} catch (IOException e) {
			throw new DSSException(String.format(
					"Unable to replace /Contents value within a toBeSigned document. Reason : %s", e.getMessage()), e);
		}
	}

	/**
	 * Parses {@code document} and extracts all revisions based on {@code %%EOF} string
	 *
	 * @param document {@link DSSDocument} PDF document to extract revisions from
	 * @return a list of {@link PdfByteRangeDocument}s representing extracted revisions
	 */
	public static List<PdfByteRangeDocument> extractRevisions(DSSDocument document) {
		assertPdfDocument(document);

		final List<PdfByteRangeDocument> revisions = new ArrayList<>();

		int position = 0;
		// line prefix compared to %%EOF
		final byte[] line = new byte[PDF_EOF_STRING.length];
		int lineLength = 0;
		// end of the last %%EOF, with its line break
		int eofPosition = 0;
		// bytes still to check for a line break after %%EOF
		int eofBytesToRead = 0;
		try (InputStream is = document.openStream()) {
			// NOTE: read by blocks, as per-byte read calls are costly on large documents
			final byte[] buffer = new byte[8192];
			int count;
			while ((count = is.read(buffer)) != -1) {
				for (int i = 0; i < count; i++) {
					byte b = buffer[i];
					++position;

					if (eofBytesToRead > 0) {
						if (DSSUtils.LINE_FEED == b) {
							// if \n or \r\n
							++eofPosition;
							eofBytesToRead = 0;
						} else if (DSSUtils.CARRIAGE_RETURN == b && eofBytesToRead == 2) {
							// if \r
							++eofPosition;
							eofBytesToRead = 1;
							continue;
						} else {
							eofBytesToRead = 0;
						}
						revisions.add(new PdfByteRangeDocument(document, getTwoIntegersByteRange(0, eofPosition)));
						continue;
					}

					if (lineLength < line.length) {
						line[lineLength] = b;
					}
					++lineLength;

					if (lineLength == line.length && Arrays.equals(PDF_EOF_STRING, line)) {
						lineLength = 0;
						eofPosition = position;
						eofBytesToRead = 2;

					} else if (DSSUtils.isLineBreakByte(b) || lineLength > line.length) {
						lineLength = 0;
					}
				}
			}

			if (eofBytesToRead > 0) {
				revisions.add(new PdfByteRangeDocument(document, getTwoIntegersByteRange(0, eofPosition)));
			}

			return revisions;

		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the last revision", e);
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
		try (InputStream is = document.openStream()) {
			return Utils.startsWith(is, PDF_PREAMBLE);
		} catch (IOException e) {
			throw new DSSException("Cannot read a sequence of bytes from the InputStream.", e);
		}
	}

	/**
	 * This method verifies whether the provided document is a PDF.
	 * If the document is not a PDF, it throws an exception
	 *
	 * @param document {@link DSSDocument}
	 * @throws IllegalArgumentException if a document of a wrong class is provided
	 * @throws IllegalInputException if a document of a different format is provided
	 */
	public static void assertPdfDocument(DSSDocument document) {
		Objects.requireNonNull(document, "DSSDocument cannot be null!");
		if (document instanceof DigestDocument) {
			throw new IllegalArgumentException("DigestDocument cannot be used! PDF document is expected!");
		}
		if (!PAdESUtils.isPDFDocument(document)) {
			throw new IllegalInputException(String.format("The document with name '%s' is not a PDF. " +
					"PDF document is expected!", document.getName()));
		}
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
