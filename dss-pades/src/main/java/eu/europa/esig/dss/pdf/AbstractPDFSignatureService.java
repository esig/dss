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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.alert.status.Status;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.exception.InvalidPasswordException;
import eu.europa.esig.dss.pades.validation.ByteRange;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PdfModification;
import eu.europa.esig.dss.pades.validation.PdfModificationDetection;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.PdfSignatureField;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pades.validation.dss.PdfCompositeDssDictionary;
import eu.europa.esig.dss.pdf.visible.SignatureDrawer;
import eu.europa.esig.dss.pdf.visible.SignatureDrawerFactory;
import eu.europa.esig.dss.pdf.visible.SignatureFieldBoxBuilder;
import eu.europa.esig.dss.pdf.visible.VisualSignatureFieldAppearance;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The abstract implementation of a PDF signature service
 */
public abstract class AbstractPDFSignatureService implements PDFSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractPDFSignatureService.class);

	/** The executed service mode */
	private final PDFServiceMode serviceMode;

	/** The signature drawer factory to use for a visual signature/timestamp creation */
	private final SignatureDrawerFactory signatureDrawerFactory;

	/**
	 * This variable set the behavior to follow in case of overlapping a new
	 * signature field with existing annotations.
	 * 
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert alertOnSignatureFieldOverlap = new ExceptionOnStatusAlert();

	/**
	 * This variable allows setting a behavior when
	 * a new signature field is created outside the page dimensions
	 *
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert alertOnSignatureFieldOutsidePageDimensions = new ExceptionOnStatusAlert();

	/**
	 * This variable indicates a behavior for creation of a new signature
	 * in a document that does not permit a new signature creation
	 *
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert alertOnForbiddenSignatureCreation = new ExceptionOnStatusAlert();

	/**
	 * This variable sets the maximal amount of pages in a PDF to execute visual
	 * screenshot comparison for Example: for value 10, the visual comparison will
	 * be executed for a PDF containing 10 and less pages
	 * 
	 * Default : 10 pages
	 */
	private int maximalPagesAmountForVisualComparison = 10;

	/**
	 * Constructor for the PDFSignatureService
	 * 
	 * @param serviceMode            current instance is used to generate
	 *                               Signature or DocumentTimeStamp revision
	 * @param signatureDrawerFactory the factory of {@code SignatureDrawer}
	 */
	protected AbstractPDFSignatureService(PDFServiceMode serviceMode, SignatureDrawerFactory signatureDrawerFactory) {
		Objects.requireNonNull(serviceMode, "The PDFServiceMode shall be defined!");
		Objects.requireNonNull(signatureDrawerFactory, "The SignatureDrawerFactory shall be defined!");
		this.serviceMode = serviceMode;
		this.signatureDrawerFactory = signatureDrawerFactory;
	}

	/**
	 * Sets alert on a signature field overlap with existing fields or/and
	 * annotations
	 * 
	 * Default : ExceptionOnStatusAlert - throw the exception
	 * 
	 * @param alertOnSignatureFieldOverlap {@link StatusAlert} to execute
	 */
	public void setAlertOnSignatureFieldOverlap(StatusAlert alertOnSignatureFieldOverlap) {
		Objects.requireNonNull(alertOnSignatureFieldOverlap, "StatusAlert cannot be null!");
		this.alertOnSignatureFieldOverlap = alertOnSignatureFieldOverlap;
	}

	/**
	 * Sets a behavior to follow when a new signature field is created outside the page's dimensions
	 *
	 * Default : ExceptionOnStatusAlert - throw the exception
	 *
	 * @param alertOnSignatureFieldOutsidePageDimensions {@link StatusAlert} to execute
	 */
	public void setAlertOnSignatureFieldOutsidePageDimensions(StatusAlert alertOnSignatureFieldOutsidePageDimensions) {
		this.alertOnSignatureFieldOutsidePageDimensions = alertOnSignatureFieldOutsidePageDimensions;
	}

	/**
	 * Sets a behavior to follow when creating a new signature in a document that forbids creation of new signatures
	 *
	 * Default : ExceptionOnStatusAlert - throw the exception
	 *
	 * @param alertOnForbiddenSignatureCreation {@link StatusAlert} to execute
	 */
	public void setAlertOnForbiddenSignatureCreation(StatusAlert alertOnForbiddenSignatureCreation) {
		this.alertOnForbiddenSignatureCreation = alertOnForbiddenSignatureCreation;
	}

	/**
	 * Sets a maximal pages amount in a PDF to process a visual screenshot
	 * comparison Example: for value 10, the visual comparison will be executed for
	 * a PDF containing 10 and less pages
	 * 
	 * NOTE: In order to disable visual comparison check set the pages amount to 0
	 * (zero)
	 * 
	 * Default : 10 pages
	 * 
	 * 
	 * @param pagesAmount the amount of the pages to execute visual comparison for
	 */
	public void setMaximalPagesAmountForVisualComparison(int pagesAmount) {
		this.maximalPagesAmountForVisualComparison = pagesAmount;
	}

	/**
	 * Returns a SignatureDrawer initialized from a provided
	 * {@code signatureDrawerFactory}
	 * 
	 * @param imageParameters {@link SignatureImageParameters} to use
	 * @return {@link SignatureDrawer}
	 */
	protected SignatureDrawer loadSignatureDrawer(SignatureImageParameters imageParameters) {
		SignatureDrawer signatureDrawer = signatureDrawerFactory.getSignatureDrawer(imageParameters);
		if (signatureDrawer == null) {
			throw new IllegalArgumentException("SignatureDrawer shall be defined for the used SignatureDrawerFactory!");
		}
		return signatureDrawer;
	}

	/**
	 * Checks if a DocumentTimestamp has to be added in the current mode
	 *
	 * @return TRUE if it is a DocumentTimestamp layer, FALSE otherwise
	 */
	protected boolean isDocumentTimestampLayer() {
		// CONTENT_TIMESTAMP is part of the signature
		return PDFServiceMode.SIGNATURE_TIMESTAMP == serviceMode || PDFServiceMode.ARCHIVE_TIMESTAMP == serviceMode;
	}

	/**
	 * Gets the type of the signature dictionary
	 *
	 * @return {@link String}
	 */
	protected String getType() {
		if (isDocumentTimestampLayer()) {
			return PAdESConstants.TIMESTAMP_TYPE;
		} else {
			return PAdESConstants.SIGNATURE_TYPE;
		}
	}

	/**
	 * This method checks if the document is not encrypted or with limited edition rights
	 * 
	 * @param pdfDocumentReader {@link PdfDocumentReader} to check
	 */
	protected void checkDocumentPermissions(final PdfDocumentReader pdfDocumentReader) {
		pdfDocumentReader.checkDocumentPermissions();
	}

	/**
	 * This method verifies whether a new signature is permitted
	 *
	 * @param reader {@link PdfDocumentReader}
	 * @param fieldParameters {@link SignatureFieldParameters}
	 */
	protected void checkNewSignatureIsPermitted(final PdfDocumentReader reader,
												final SignatureFieldParameters fieldParameters) {
		final CertificationPermission certificationPermission = reader.getCertificationPermission();
		if (isDocumentChangeForbidden(certificationPermission)) {
			alertOnForbiddenSignatureCreation();
		}
		if (reader.isUsageRightsSignaturePresent()) {
			/*
			 * Deprecated. See ISO 32000-2:
			 *
			 * When a usage rights signature is present, it is up to the PDF processor or
			 * to the signature handler to process it or not.
			 */
			LOG.info("A usage rights signature is present. The feature is deprecated and the entry is not handled.");
		}

		try {
			String signatureFieldId = fieldParameters.getFieldId();

			Map<PdfSignatureDictionary, List<PdfSignatureField>> sigDictionaries = reader.extractSigDictionaries();
			sigDictionaries = sortSignatureDictionaries(sigDictionaries);
			for (PdfSignatureDictionary signatureDictionary : sigDictionaries.keySet()) {
				SigFieldPermissions fieldMDP = signatureDictionary.getFieldMDP();
				if (fieldMDP != null && isSignatureFieldCreationForbidden(fieldMDP, signatureFieldId)) {
					alertOnForbiddenSignatureCreation();
				}
			}

			for (List<PdfSignatureField> signatureFieldList : sigDictionaries.values()) {
				for (PdfSignatureField signatureField : signatureFieldList) {
					SigFieldPermissions lockDict = signatureField.getLockDictionary();
					if (lockDict != null && lockDict.getCertificationPermission() != null &&
							isSignatureFieldCreationForbidden(lockDict, signatureFieldId)) {
						alertOnForbiddenSignatureCreation();
					}
				}
			}

		} catch (IOException e) {
			LOG.warn("An error occurred while reading signature dictionary entries : {}", e.getMessage(), e);
		}
	}

	@Override
	public List<PdfRevision> getRevisions(final DSSDocument document, final String pwd) {
		final List<PdfRevision> revisions = new ArrayList<>();
		try (PdfDocumentReader reader = loadPdfDocumentReader(document, pwd)) {

			final PdfCompositeDssDictionary compositeDssDictionary = new PdfCompositeDssDictionary();

			final PdfDssDict dssDictionary = reader.getDSSDictionary();
			PdfDssDict lastDSSDictionary = dssDictionary; // defined the last created DSS dictionary
			compositeDssDictionary.populateFromDssDictionary(lastDSSDictionary);

			Map<PdfSignatureDictionary, List<PdfSignatureField>> sigDictionaries = reader.extractSigDictionaries();
			sigDictionaries = sortSignatureDictionaries(sigDictionaries); // sort from the latest revision to the first

			for (Map.Entry<PdfSignatureDictionary, List<PdfSignatureField>> sigDictEntry : sigDictionaries.entrySet()) {
				PdfSignatureDictionary signatureDictionary = sigDictEntry.getKey();
				List<PdfSignatureField> fields = sigDictEntry.getValue();
				List<String> fieldNames = fields.stream().map(f -> f.getFieldName()).collect(Collectors.toList());

				try {
					LOG.info("Signature fields: {}", fieldNames);

					final ByteRange byteRange = signatureDictionary.getByteRange();
					byteRange.validate();

					final byte[] cms = signatureDictionary.getContents();
					byte[] revisionContent = DSSUtils.EMPTY_BYTE_ARRAY;
					if (!isContentValueEqualsByteRangeExtraction(document, byteRange, cms, fieldNames)) {
						LOG.warn("Signature {} is invalid. SIWA detected !", fieldNames);
					} else {
						revisionContent = PAdESUtils.getRevisionContent(document, byteRange);
					}

					boolean signatureCoversWholeDocument = reader.isSignatureCoversWholeDocument(signatureDictionary);
					byte[] signedData = PAdESUtils.getSignedContentFromRevision(revisionContent, byteRange);
					DSSDocument signedContent = new InMemoryDocument(signedData);

					// create a DSS revision if updated
					lastDSSDictionary = getPreviousDssDictAndUpdateIfNeeded(revisions, compositeDssDictionary,
							lastDSSDictionary, revisionContent, pwd);

					PdfCMSRevision newRevision = null;
					if (isDocTimestamp(signatureDictionary)) {
						newRevision = new PdfDocTimestampRevision(signatureDictionary, fields, signedContent,
								signatureCoversWholeDocument);

					} else if (isSignature(signatureDictionary)) {
						// signature contains all dss dictionaries present after
						newRevision = new PdfSignatureRevision(signatureDictionary, compositeDssDictionary,
								dssDictionary, fields, signedContent, signatureCoversWholeDocument);

					} else {
						LOG.warn("The entry {} is skipped. A signature dictionary entry with a type '{}' " +
										"and subFilter '{}' is not acceptable configuration!", fieldNames,
								signatureDictionary.getType(), signatureDictionary.getSubFilter());

					}

					// add signature/timestamp revision
					if (newRevision != null) {
						revisions.add(newRevision);
					}

					// checks if there is a previous update of the DSS dictionary and creates a new revision if needed
					lastDSSDictionary = getPreviousDssDictAndUpdateIfNeeded(revisions, compositeDssDictionary,
							lastDSSDictionary, extractBeforeSignatureValue(byteRange, revisionContent), pwd);


				} catch (Exception e) {
					String errorMessage = "Unable to parse signature {} . Reason : {}";
					if (LOG.isDebugEnabled()) {
						LOG.error(errorMessage, fieldNames, e.getMessage(), e);
					} else {
						LOG.error(errorMessage, fieldNames, e.getMessage());
					}

				}
			}

		} catch (IOException e) {
			throw new DSSException(String.format(
					"The document with name [%s] is either not accessible or not PDF compatible. Reason : [%s]",
					document.getName(), e.getMessage()), e);
		} catch (DSSException e) {
			throw e;
		} catch (Exception e) {
			throw new DSSException("Cannot analyze signatures : " + e.getMessage(), e);
		}
		return revisions;
	}

	@Override
	public DSSDocument addDssDictionary(DSSDocument document, PdfValidationDataContainer validationDataForInclusion) {
		return addDssDictionary(document, validationDataForInclusion, null);
	}

	@Override
	public List<String> getAvailableSignatureFields(final DSSDocument document) {
		return getAvailableSignatureFields(document, null);
	}

	@Override
	public DSSDocument addNewSignatureField(DSSDocument document, SignatureFieldParameters parameters) {
		return addNewSignatureField(document, parameters, null);
	}

	/**
	 * Loads {@code PdfDocumentReader} instance
	 * 
	 * @param dssDocument        {@link DSSDocument} to read
	 * @param passwordProtection {@link String} the password used to protect the
	 *                           document
	 * @return {@link PdfDocumentReader}
	 * @throws IOException              in case of loading error
	 * @throws InvalidPasswordException if the password is not provided or invalid
	 *                                  for a protected document
	 */
	protected abstract PdfDocumentReader loadPdfDocumentReader(DSSDocument dssDocument, String passwordProtection)
			throws IOException, InvalidPasswordException;

	/**
	 * Loads {@code PdfDocumentReader} instance
	 * 
	 * @param binaries           a byte array
	 * @param passwordProtection {@link String} the password used to protect the
	 *                           document
	 * @return {@link PdfDocumentReader}
	 * @throws IOException              in case of loading error
	 * @throws InvalidPasswordException if the password is not provided or invalid
	 *                                  for a protected document
	 */
	protected abstract PdfDocumentReader loadPdfDocumentReader(byte[] binaries, String passwordProtection)
			throws IOException, InvalidPasswordException;

	/**
	 * Sorts the given map starting from the latest revision to the first
	 * 
	 * @param pdfSignatureDictionary a map between {@link PdfSignatureDictionary}
	 *                               and list of field names to sort
	 * @return a sorted map
	 */
	private Map<PdfSignatureDictionary, List<PdfSignatureField>> sortSignatureDictionaries(
			Map<PdfSignatureDictionary, List<PdfSignatureField>> pdfSignatureDictionary) {
		return pdfSignatureDictionary.entrySet().stream()
				.sorted(Map.Entry.<PdfSignatureDictionary, List<PdfSignatureField>>comparingByKey(
						new PdfSignatureDictionaryComparator()).reversed())
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
						(oldValue, newValue) -> oldValue, LinkedHashMap::new));
	}

	private PdfDssDict getPreviousDssDictAndUpdateIfNeeded(List<PdfRevision> revisions,
														   PdfCompositeDssDictionary compositeDssDictionary,
														   PdfDssDict lastDSSDictionary,
														   byte[] dssDictionaryRevision, String pwd) {
		PdfDssDict currentDssDict = getDSSDictionaryPresentInRevision(dssDictionaryRevision, pwd);
		if (lastDSSDictionary != null && !lastDSSDictionary.equals(currentDssDict)) {
			compositeDssDictionary.populateFromDssDictionary(lastDSSDictionary);
			revisions.add(new PdfDocDssRevision(compositeDssDictionary, lastDSSDictionary));
		}
		return currentDssDict;
	}

	private PdfDssDict getDSSDictionaryPresentInRevision(final byte[] originalBytes, final String pwd) {
		if (Utils.isArrayEmpty(originalBytes)) {
			return null;
		}

		try (PdfDocumentReader reader = loadPdfDocumentReader(originalBytes, pwd)) {
			return reader.getDSSDictionary();
		} catch (Exception e) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Cannot extract DSS dictionary from the previous revision : {}", e.getMessage());
			}
			return null;
		}
	}

	/**
	 * Checks if the of the value incorporated into /Contents matches the range defined in the {@code byteRange}
	 *
	 * NOTE: used for SIWA detection
	 *
	 * @param document {@link DSSDocument} to be validated
	 * @param byteRange {@link ByteRange}
	 * @param cms binaries of the CMSSignedData
	 * @param signatureFieldNames a list of signature field {@link String} names
	 * @return TRUE if the content value equals the byte range extraction, FALSE otherwise
	 */
	protected boolean isContentValueEqualsByteRangeExtraction(DSSDocument document, ByteRange byteRange, byte[] cms,
			List<String> signatureFieldNames) {
		boolean match = false;
		try {
			byte[] cmsWithByteRange = getSignatureValue(document, byteRange);
			match = Arrays.equals(cms, cmsWithByteRange);
			if (!match) {
				LOG.warn("Conflict between /Content and ByteRange for Signature {}.", signatureFieldNames);
			}
		} catch (Exception e) {
			String message = String.format("Unable to retrieve data from the ByteRange : [%s]", byteRange);
			if (LOG.isDebugEnabled()) {
				// Exception displays the (long) hex value
				LOG.error(message, e);
			} else {
				LOG.error(message);
			}
		}
		return match;
	}

	/**
	 * Gets the SignatureValue from the {@code dssDocument} according to the {@code byteRange}
	 *
	 * Example: extracts bytes from 841 to 959. [0, 840, 960, 1200]
	 *
	 * @param dssDocument {@link DSSDocument} to process
	 * @param byteRange {@link ByteRange} specifying the signatureValue
	 * @return signatureValue binaries
	 * @throws IOException if an exception occurs
	 */
	protected byte[] getSignatureValue(DSSDocument dssDocument, ByteRange byteRange) throws IOException {
		int startSigValueContent = byteRange.getFirstPartStart() + byteRange.getFirstPartEnd() + 1;
		int endSigValueContent = byteRange.getSecondPartStart() - 1;

		int signatureValueArraySize = endSigValueContent - startSigValueContent;
		if (signatureValueArraySize < 1) {
			throw new DSSException("The byte range present in the document is not valid! "
					+ "SignatureValue size cannot be negative or equal to zero!");
		}

		byte[] signatureValueArray = new byte[signatureValueArraySize];

		try (InputStream is = dssDocument.openStream()) {
			DSSUtils.skipAvailableBytes(is, startSigValueContent);
			DSSUtils.readAvailableBytes(is, signatureValueArray);
		}

		return Utils.fromHex(new String(signatureValueArray));
	}

	/**
	 * Extract the content before the signature value
	 *
	 * @param byteRange {@link ByteRange}
	 * @param signedContent byte array representing the signed content
	 * @return the first part of the byte range
	 */
	protected byte[] extractBeforeSignatureValue(ByteRange byteRange, byte[] signedContent) {
		final int length = byteRange.getFirstPartEnd();
		if (signedContent.length < length) {
			return new byte[0];
		}
		return PAdESUtils.retrievePreviousPDFRevision(new InMemoryDocument(signedContent), byteRange).getBytes();
	}

	/**
	 * Checks if the given signature dictionary represents a DocTimeStamp
	 * 
	 * @param pdfSigDict {@link PdfSignatureDictionary} to check
	 * @return TRUE if the signature dictionary represents a DocTimeStamp, FALSE
	 *         otherwise
	 */
	protected boolean isDocTimestamp(PdfSignatureDictionary pdfSigDict) {
		String type = pdfSigDict.getType();
		String subFilter = pdfSigDict.getSubFilter();
		/* Support historical TS 102 778-4 and new EN 319 142-1 */
		return (type == null || PAdESConstants.TIMESTAMP_TYPE.equals(type))
				&& PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER.equals(subFilter);
	}

	/**
	 * Checks if the given signature dictionary represents a Signature
	 * 
	 * @param pdfSigDict {@link PdfSignatureDictionary} to check
	 * @return TRUE if the signature dictionary represents a Signature, FALSE
	 *         otherwise
	 */
	protected boolean isSignature(PdfSignatureDictionary pdfSigDict) {
		String type = pdfSigDict.getType();
		String subFilter = pdfSigDict.getSubFilter();
		/* Support historical TS 102 778-4 and new EN 319 142-1 */
		return (type == null || PAdESConstants.SIGNATURE_TYPE.equals(type))
				&& !PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER.equals(subFilter);
	}

	/**
	 * Checks validity of the SignatureField position and returns the calculated signature field box
	 * 
	 * @param signatureDrawer {@link SignatureDrawer}
	 * @param documentReader  {@link PdfDocumentReader}
	 * @param fieldParameters {@link SignatureFieldParameters}
	 * @return {@link AnnotationBox}
	 * @throws IOException if an exception occurs
	 */
	protected AnnotationBox getVisibleSignatureFieldBoxPosition(SignatureDrawer signatureDrawer,
													   PdfDocumentReader documentReader,
													   SignatureFieldParameters fieldParameters) throws IOException {
		AnnotationBox signatureFieldAnnotation = buildSignatureFieldBox(signatureDrawer);
		if (signatureFieldAnnotation != null) {
			AnnotationBox pageBox = documentReader.getPageBox(fieldParameters.getPage());
			int pageRotation = documentReader.getPageRotation(fieldParameters.getPage());
			signatureFieldAnnotation = toPdfPageCoordinates(signatureFieldAnnotation, pageBox, pageRotation);

			assertSignatureFieldPositionValid(signatureFieldAnnotation, documentReader, fieldParameters);
		}
		return signatureFieldAnnotation;
	}

	/**
	 * Returns a SignatureFieldBox. Used for a SignatureField position validation.
	 * 
	 * @param signatureDrawer {@link SignatureDrawer}
	 * @return {@link AnnotationBox}
	 * @throws IOException if an exception occurs
	 */
	protected AnnotationBox buildSignatureFieldBox(SignatureDrawer signatureDrawer) throws IOException {
		if (signatureDrawer instanceof SignatureFieldBoxBuilder) {
			SignatureFieldBoxBuilder signatureFieldBoxBuilder = (SignatureFieldBoxBuilder) signatureDrawer;
			VisualSignatureFieldAppearance signatureFieldBox = signatureFieldBoxBuilder.buildSignatureFieldBox();
			if (signatureFieldBox != null) {
				return signatureFieldBox.getAnnotationBox();
			}
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("The used SignatureDrawer shall be an instance of VisibleSignatureFieldBoxBuilder "
					+ "in order to verify a SignatureField position!");
		}
		return null;
	}

	/**
	 * Checks if the signatureFieldBox overlaps with any existing annotations on the
	 * given page and returns the respectful signature field box
	 * 
	 * @param reader     {@link PdfDocumentReader} to be validated
	 * @param parameters {@link SignatureFieldParameters}
	 * @return {@link AnnotationBox} computed signature field box
	 * @throws IOException if an exception occurs
	 */
	protected AnnotationBox getVisibleSignatureFieldBoxPosition(final PdfDocumentReader reader,
																SignatureFieldParameters parameters) throws IOException {
		AnnotationBox annotationBox = new AnnotationBox(parameters);
		AnnotationBox pageBox = reader.getPageBox(parameters.getPage());
		int pageRotation = reader.getPageRotation(parameters.getPage());
		annotationBox = toPdfPageCoordinates(annotationBox, pageBox, pageRotation);

		assertSignatureFieldPositionValid(annotationBox, reader, parameters);
		return annotationBox;
	}

	/**
	 * This method transforms a {@code fieldAnnotationBox}'s positions and dimensions according to the given page
	 *
	 * @param fieldAnnotationBox {@link AnnotationBox} computed field of a signature
	 * @param pageBox {@link AnnotationBox} page's box
	 * @param pageRotation defines the page's rotation
	 * @return {@link AnnotationBox}
	 */
	protected AnnotationBox toPdfPageCoordinates(AnnotationBox fieldAnnotationBox, AnnotationBox pageBox, int pageRotation) {
		return fieldAnnotationBox.toPdfPageCoordinates(pageBox.getHeight());
	}

	private void assertSignatureFieldPositionValid(AnnotationBox annotationBox, final PdfDocumentReader reader,
												  SignatureFieldParameters parameters) throws IOException {
		int pageRotation = reader.getPageRotation(parameters.getPage());
		AnnotationBox pageBox = reader.getPageBox(parameters.getPage());
		checkSignatureFieldAgainstPageDimensions(annotationBox, pageBox, pageRotation);
		List<PdfAnnotation> pdfAnnotations = reader.getPdfAnnotations(parameters.getPage());
		checkSignatureFieldBoxOverlap(annotationBox, pdfAnnotations);
	}

	/**
	 * This method verifies whether the {@code signatureFieldBox} overlaps
	 * with one of the extracted {@code pdfAnnotations}
	 *
	 * @param signatureFieldBox {@link AnnotationBox} to verify
	 * @param pdfAnnotations a list of {@link AnnotationBox} to verify against
	 */
	protected void checkSignatureFieldBoxOverlap(final AnnotationBox signatureFieldBox, List<PdfAnnotation> pdfAnnotations) {
		if (PdfModificationDetectionUtils.isAnnotationBoxOverlapping(signatureFieldBox, pdfAnnotations)) {
			alertOnSignatureFieldOverlap();
		}
	}

	/**
	 * Executes the alert {@code alertOnSignatureFieldOverlap}
	 */
	private void alertOnSignatureFieldOverlap() {
		String alertMessage = "The new signature field position overlaps with an existing annotation!";
		alertOnSignatureFieldOverlap.alert(new Status(alertMessage));
	}

	/**
	 * This method verifies whether the {@code signatureFieldBox} is within {@code pageBox}
	 *
	 * @param signatureFieldBox {@link AnnotationBox} to check
	 * @param pageBox {@link AnnotationBox} representing the page's box
	 * @param pageRotation defines the page's rotation
	 */
	protected void checkSignatureFieldAgainstPageDimensions(final AnnotationBox signatureFieldBox, AnnotationBox pageBox,
															int pageRotation) {
		if (signatureFieldBox.getMinX() < pageBox.getMinX() || signatureFieldBox.getMaxX() > pageBox.getMaxX() ||
				signatureFieldBox.getMinY() < pageBox.getMinY() || signatureFieldBox.getMaxY() > pageBox.getMaxY()) {
			alertOnSignatureFieldOutsidePageDimensions(signatureFieldBox, pageBox);
		}
	}

	private void alertOnSignatureFieldOutsidePageDimensions(final AnnotationBox signatureFieldBox,
															final AnnotationBox pageBox) {
		String alertMessage = String.format("The new signature field position is outside the page dimensions! " +
				"Signature Field : [minX=%s, maxX=%s, minY=%s, maxY=%s], " +
				"Page : [minX=%s, maxX=%s, minY=%s, maxY=%s]",
				signatureFieldBox.getMinX(), signatureFieldBox.getMaxX(), signatureFieldBox.getMinY(), signatureFieldBox.getMaxY(),
				pageBox.getMinX(), pageBox.getMaxX(), pageBox.getMinY(), pageBox.getMaxY());
		alertOnSignatureFieldOutsidePageDimensions.alert(new Status(alertMessage));
	}

	@Override
	public void analyzePdfModifications(DSSDocument document, List<AdvancedSignature> signatures, String pwd) {
		try (PdfDocumentReader finalRevisionReader = loadPdfDocumentReader(document, pwd)) {
			for (AdvancedSignature signature : signatures) {
				PAdESSignature padesSignature = (PAdESSignature) signature;
				PdfSignatureRevision pdfRevision = padesSignature.getPdfRevision();
				byte[] revisionContent = PAdESUtils.getRevisionContent(document, pdfRevision.getByteRange());
				pdfRevision.setModificationDetection(getModificationDetection(finalRevisionReader, new InMemoryDocument(revisionContent), pwd));
			}

		} catch (Exception e) {
			String errorMessage = "Unable to proceed PDF modification detection. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.error(errorMessage, e.getMessage(), e);
			} else {
				LOG.error(errorMessage, e.getMessage());
			}
		}
	}

	private PdfModificationDetection getModificationDetection(PdfDocumentReader finalRevisionReader, DSSDocument originalDocument, String pwd) throws IOException {
		try (PdfDocumentReader signedRevisionReader = loadPdfDocumentReader(originalDocument , pwd)) {
			PdfModificationDetectionImpl pdfModificationDetection = new PdfModificationDetectionImpl();

			pdfModificationDetection.setAnnotationOverlaps(
					PdfModificationDetectionUtils.getAnnotationOverlaps(finalRevisionReader));
			pdfModificationDetection.setPageDifferences(
					PdfModificationDetectionUtils.getPagesDifferences(signedRevisionReader, finalRevisionReader));
			pdfModificationDetection.setVisualDifferences(
					getVisualDifferences(signedRevisionReader, finalRevisionReader));

			Set<ObjectModification> modificationsSet =
					PdfModificationDetectionUtils.getModificationSet(signedRevisionReader, finalRevisionReader);
			pdfModificationDetection.setObjectModifications(new PdfObjectModificationsFilter(modificationsSet).filter());

			return pdfModificationDetection;
		}
	}

	/**
	 * Returns a list of visual differences between the provided PDF and the signed
	 * content
	 * 
	 * @param signedRevisionReader {@link PdfDocumentReader} for the signed revision
	 *                             content
	 * @param finalRevisionReader  {@link PdfDocumentReader} for the input PDF
	 *                             document
	 * @return a list of {@link PdfModification}s
	 * @throws IOException if an exception occurs
	 */
	protected List<PdfModification> getVisualDifferences(final PdfDocumentReader signedRevisionReader,
			final PdfDocumentReader finalRevisionReader) throws IOException {
		int pagesAmount = finalRevisionReader.getNumberOfPages();
		if (maximalPagesAmountForVisualComparison >= pagesAmount) {
			return PdfModificationDetectionUtils.getVisualDifferences(signedRevisionReader, finalRevisionReader);
		} else {
			LOG.debug("The provided document contains {} pages, while the limit for a visual comparison is set to {}.",
					pagesAmount, maximalPagesAmountForVisualComparison);
		}
		return Collections.emptyList();
	}

	private boolean isDocumentChangeForbidden(CertificationPermission certificationPermission) {
		return CertificationPermission.NO_CHANGE_PERMITTED.equals(certificationPermission);
	}

	private void alertOnForbiddenSignatureCreation() {
		String errorMessage = "The creation of new signatures is not permitted in the current document.";
		alertOnForbiddenSignatureCreation.alert(new Status(errorMessage));
	}

	private boolean isSignatureFieldCreationForbidden(SigFieldPermissions sigFieldPermissions, String signatureFieldId) {
		switch (sigFieldPermissions.getAction()) {
			case ALL:
				return true;
			case INCLUDE:
				if (Utils.isStringEmpty(signatureFieldId)) {
					return false;
				}
				if (sigFieldPermissions.getFields().contains(signatureFieldId)) {
					return true;
				}
				break;
			case EXCLUDE:
				if (Utils.isStringEmpty(signatureFieldId)) {
					return true;
				}
				if (!sigFieldPermissions.getFields().contains(signatureFieldId)) {
					return true;
				}
				break;
			default:
				throw new UnsupportedOperationException(
						String.format("The action value '%s' is not supported!", sigFieldPermissions.getAction()));
		}
		CertificationPermission certificationPermission = sigFieldPermissions.getCertificationPermission();
		return CertificationPermission.NO_CHANGE_PERMITTED.equals(certificationPermission);
	}

}
