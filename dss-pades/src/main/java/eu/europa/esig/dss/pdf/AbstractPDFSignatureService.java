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

import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESCommonParameters;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.exception.InvalidPasswordException;
import eu.europa.esig.dss.pades.validation.ByteRange;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.PdfSignatureField;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pades.validation.dss.PdfCompositeDssDictionary;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.pdf.modifications.PdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.PdfModification;
import eu.europa.esig.dss.pdf.modifications.PdfModificationDetection;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModificationsFinder;
import eu.europa.esig.dss.pdf.visible.SignatureDrawer;
import eu.europa.esig.dss.pdf.visible.SignatureDrawerFactory;
import eu.europa.esig.dss.pdf.visible.SignatureFieldBoxBuilder;
import eu.europa.esig.dss.pdf.visible.VisualSignatureFieldAppearance;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandler;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
	 * The builder to be used to create a new {@code DSSResourcesHandler} for each internal call,
	 * defining a way working with internal resources (e.g. in memory or by using temporary files).
	 * The resources are used on a document creation
	 *
	 * Default : {@code eu.europa.esig.dss.signature.resources.InMemoryResourcesHandler}, working with data in memory
	 */
	protected DSSResourcesHandlerBuilder resourcesHandlerBuilder = PAdESUtils.DEFAULT_RESOURCES_HANDLER_BUILDER;

	/**
	 * Used to find differences occurred between PDF revisions (e.g. visible changes).
	 *
	 * Default : {@code DefaultPdfDifferencesFinder}
	 */
	protected PdfDifferencesFinder pdfDifferencesFinder = new DefaultPdfDifferencesFinder();

	/**
	 * Used to find differences within internal PDF objects occurred between PDF revisions .
	 *
	 * Default : {@code DefaultPdfModificationsFinder}
	 */
	protected PdfObjectModificationsFinder pdfObjectModificationsFinder = new DefaultPdfObjectModificationsFinder();

	/**
	 * Used to verify PDF document permissions regarding a new signature creation
	 */
	protected PdfPermissionsChecker pdfPermissionsChecker = new PdfPermissionsChecker();

	/**
	 * Used to verify the signature field position placement validity
	 */
	protected PdfSignatureFieldPositionChecker pdfSignatureFieldPositionChecker = new PdfSignatureFieldPositionChecker();

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

	@Override
	public void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
		Objects.requireNonNull(resourcesHandlerBuilder, "DSSResourcesFactoryBuilder cannot be null!");
		this.resourcesHandlerBuilder = resourcesHandlerBuilder;
	}

	@Override
	public void setPdfDifferencesFinder(PdfDifferencesFinder pdfDifferencesFinder) {
		Objects.requireNonNull(pdfDifferencesFinder, "PdfDifferencesFinder cannot be null!");
		this.pdfDifferencesFinder = pdfDifferencesFinder;
	}

	@Override
	public void setPdfObjectModificationsFinder(PdfObjectModificationsFinder pdfObjectModificationsFinder) {
		Objects.requireNonNull(pdfObjectModificationsFinder, "PdfObjectModificationsFinder cannot be null!");
		this.pdfObjectModificationsFinder = pdfObjectModificationsFinder;
	}

	@Override
	public void setPdfPermissionsChecker(PdfPermissionsChecker pdfPermissionsChecker) {
		Objects.requireNonNull(pdfPermissionsChecker, "PdfPermissionsChecker cannot be null!");
		this.pdfPermissionsChecker = pdfPermissionsChecker;
	}

	@Override
	public void setPdfSignatureFieldPositionChecker(PdfSignatureFieldPositionChecker pdfSignatureFieldPositionChecker) {
		Objects.requireNonNull(pdfSignatureFieldPositionChecker, "PdfSignatureFieldPositionChecker cannot be null!");
		this.pdfSignatureFieldPositionChecker = pdfSignatureFieldPositionChecker;
	}

	/**
	 * Sets alert on a signature field overlap with existing fields or/and
	 * annotations
	 * 
	 * Default : ExceptionOnStatusAlert - throw the exception
	 * 
	 * @param alertOnSignatureFieldOverlap {@link StatusAlert} to execute
	 * @deprecated since DSS 5.12. Use {@code
	 * 				PdfSignatureFieldPositionChecker pdfSignatureFieldPositionChecker = new PdfSignatureFieldPositionChecker();
	 *				pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOverlap(alertOnSignatureFieldOutsidePageDimensions);
	 *			    pdfSignatureService.setPdfSignatureFieldPositionChecker(pdfSignatureFieldPositionChecker);
	 * 			}
	 */
	@Deprecated
	public void setAlertOnSignatureFieldOverlap(StatusAlert alertOnSignatureFieldOverlap) {
		LOG.warn("Use of deprecated method setAlertOnSignatureFieldOverlap(alertOnSignatureFieldOverlap)!");
		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOverlap(alertOnSignatureFieldOverlap);
	}

	/**
	 * Sets a behavior to follow when a new signature field is created outside the page's dimensions
	 *
	 * Default : ExceptionOnStatusAlert - throw the exception
	 *
	 * @param alertOnSignatureFieldOutsidePageDimensions {@link StatusAlert} to execute
	 * @deprecated since DSS 5.12. Use {@code
	 * 				PdfSignatureFieldPositionChecker pdfSignatureFieldPositionChecker = new PdfSignatureFieldPositionChecker();
	 *				pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(alertOnSignatureFieldOutsidePageDimensions);
	 *			    pdfSignatureService.setPdfSignatureFieldPositionChecker(pdfSignatureFieldPositionChecker);
	 * 			}
	 */
	@Deprecated
	public void setAlertOnSignatureFieldOutsidePageDimensions(StatusAlert alertOnSignatureFieldOutsidePageDimensions) {
		LOG.warn("Use of deprecated method setAlertOnSignatureFieldOutsidePageDimensions(alertOnSignatureFieldOutsidePageDimensions)!");
		pdfSignatureFieldPositionChecker.setAlertOnSignatureFieldOutsidePageDimensions(alertOnSignatureFieldOutsidePageDimensions);
	}

	/**
	 * Sets a behavior to follow when creating a new signature in a document that forbids creation of new signatures
	 *
	 * Default : ProtectedDocumentExceptionOnStatusAlert -
	 *                 throws the {@code eu.europa.esig.dss.pades.exception.ProtectedDocumentException} exception
	 *
	 * @param alertOnForbiddenSignatureCreation {@link StatusAlert} to execute
	 * @deprecated since DSS 5.12. Use {@code
	 * 				PdfPermissionsChecker pdfPermissionsChecker = new PdfPermissionsChecker();
	 *				pdfPermissionsChecker.setAlertOnForbiddenSignatureCreation(alertOnForbiddenSignatureCreation);
	 *			    pdfSignatureService.setPdfPermissionsChecker(pdfPermissionsChecker);
	 * 			}
	 */
	@Deprecated
	public void setAlertOnForbiddenSignatureCreation(StatusAlert alertOnForbiddenSignatureCreation) {
		LOG.warn("Use of deprecated method setAlertOnForbiddenSignatureCreation(alertOnForbiddenSignatureCreation)!");
		pdfPermissionsChecker.setAlertOnForbiddenSignatureCreation(alertOnForbiddenSignatureCreation);
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
	 * This method instantiates a new {@code DSSResourcesFactory}
	 *
	 * @return {@link DSSResourcesHandler}
	 * @throws IOException if an error occurs on DSSResourcesHandler instantiation
	 */
	protected DSSResourcesHandler instantiateResourcesHandler() throws IOException {
		return resourcesHandlerBuilder.createResourcesHandler();
	}

	@Override
	@Deprecated
	public byte[] digest(DSSDocument toSignDocument, PAdESCommonParameters parameters) {
		return messageDigest(toSignDocument, parameters).getValue();
	}

	@Override
	public DSSMessageDigest messageDigest(DSSDocument toSignDocument, PAdESCommonParameters parameters) {
		final PdfSignatureCache pdfSignatureCache = parameters.getPdfSignatureCache();
		if (pdfSignatureCache.getMessageDigest() == null) {
			final DSSMessageDigest messageDigest = computeDigest(toSignDocument, parameters);
			pdfSignatureCache.setMessageDigest(messageDigest);
		}
		return pdfSignatureCache.getMessageDigest();
	}

	/**
	 * Computes digest on to be signed data computed on the {@code toSignDocument} respectively
	 * to the given {@code parameters}
	 *
	 * @param toSignDocument {@link DSSDocument} to be signed
	 * @param parameters {@link PAdESCommonParameters}
	 * @return {@link DSSMessageDigest}
	 */
	protected abstract DSSMessageDigest computeDigest(DSSDocument toSignDocument, PAdESCommonParameters parameters);

	@Override
	public DSSDocument sign(DSSDocument toSignDocument, byte[] cmsSignedData, PAdESCommonParameters parameters) {
		final PdfSignatureCache pdfSignatureCache = parameters.getPdfSignatureCache();
		DSSDocument signedDocument = null;
		if (pdfSignatureCache.getToBeSignedDocument() != null) {
			try {
				signedDocument = PAdESUtils.replaceSignature(pdfSignatureCache.getToBeSignedDocument(),
						cmsSignedData, resourcesHandlerBuilder);
			} catch (Exception e) {
				String errorMessage = "Unable to sign document using a resources caching! Reason : '{}'. Sign using a complete processing...";
				if (LOG.isDebugEnabled()) {
					LOG.warn(errorMessage, e.getMessage(), e);
				} else {
					LOG.warn(errorMessage, e.getMessage());
				}
			}
		}
		parameters.reinit();

		if (signedDocument == null) {
			signedDocument = signDocument(toSignDocument, cmsSignedData, parameters);
		}
		signedDocument.setMimeType(MimeTypeEnum.PDF);
		return signedDocument;
	}

	/**
	 * This method creates a signed document from the original {@code toSignDocument}, incorporating a new revision,
	 * enveloping the provided {@code cmsSignedData}
	 *
	 * @param toSignDocument {@link DSSDocument} to be signed
	 * @param cmsSignedData byte array representing the encoded CMS signed data's binaries
	 * @param parameters {@link PAdESCommonParameters}
	 * @return {@link DSSDocument}
	 */
	protected abstract DSSDocument signDocument(DSSDocument toSignDocument, byte[] cmsSignedData,
												PAdESCommonParameters parameters);

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
				List<String> fieldNames = toStringNames(fields);

				try {
					LOG.info("Signature fields: {}", fieldNames);

					final ByteRange byteRange = signatureDictionary.getByteRange();
					final byte[] cms = signatureDictionary.getContents();
					final boolean byteRangeValid = validateByteRange(byteRange, document, cms);
					byteRange.setValid(byteRangeValid);

					byte[] revisionContent = PAdESUtils.getRevisionContent(document, byteRange);
					byte[] signedData = DSSUtils.EMPTY_BYTE_ARRAY;
					if (byteRangeValid) {
						signedData = PAdESUtils.getSignedContentFromRevision(revisionContent, byteRange);
					} else {
						LOG.warn("The signature '{}' has an invalid /ByteRange! " +
								"The validation will result to a broken signature.", fieldNames);
					}

					final DSSDocument signedContent = new InMemoryDocument(signedData);
					final boolean signatureCoversWholeDocument = reader.isSignatureCoversWholeDocument(signatureDictionary);

					try (PdfDocumentReader revisionReader = loadPdfDocumentReader(revisionContent, pwd)) {

						// Method is used to detect modification within the signature dictionary itself (spoofing attack)
						verifyPdfSignatureDictionary(signatureDictionary, fieldNames, revisionReader);

						// create a DSS revision if updated
						lastDSSDictionary = getPreviousDssDictAndUpdateIfNeeded(revisions, compositeDssDictionary,
								lastDSSDictionary, revisionReader.getDSSDictionary());

					} catch (Exception e) {
						if (LOG.isDebugEnabled()) {
							LOG.debug("Cannot read signature revision '{}' : {}", fieldNames, e.getMessage());
						}
					}


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


					try (PdfDocumentReader revisionReader = loadPdfDocumentReader(
							extractBeforeSignatureValue(byteRange, revisionContent), pwd)) {

						// checks if there is a previous update of the DSS dictionary and creates a new revision if needed
						lastDSSDictionary = getPreviousDssDictAndUpdateIfNeeded(revisions, compositeDssDictionary,
								lastDSSDictionary, revisionReader.getDSSDictionary());

					} catch (Exception e) {
						// do nothing
					}


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

	private void verifyPdfSignatureDictionary(PdfSignatureDictionary signatureDictionary, List<String> fieldNames,
											  PdfDocumentReader revisionReader) throws IOException {
		PdfSignatureDictionary signatureDictionaryToCompare = getSignatureDictionaryForFieldNames(fieldNames, revisionReader);
		if (!signatureDictionary.checkConsistency(signatureDictionaryToCompare)) {
			LOG.warn("The signature dictionary for signature {} is not consistent!", fieldNames);
		}
	}

	private PdfSignatureDictionary getSignatureDictionaryForFieldNames(List<String> fieldNames,
																	   PdfDocumentReader revisionReader) throws IOException{
		Map<PdfSignatureDictionary, List<PdfSignatureField>> pdfSignatureDictionaryListMap = revisionReader.extractSigDictionaries();
		for (Map.Entry<PdfSignatureDictionary, List<PdfSignatureField>> entry : pdfSignatureDictionaryListMap.entrySet()) {
			PdfSignatureDictionary signatureDictionary = entry.getKey();
			List<PdfSignatureField> signatureFields = entry.getValue();
			if (fieldNames.equals(toStringNames(signatureFields))) {
				return signatureDictionary;
			}
		}
		return null;
	}

	private List<String> toStringNames(List<PdfSignatureField> signatureFields) {
		return signatureFields.stream().map(PdfSignatureField::getFieldName).collect(Collectors.toList());
	}

	private PdfDssDict getPreviousDssDictAndUpdateIfNeeded(List<PdfRevision> revisions,
														   PdfCompositeDssDictionary compositeDssDictionary,
														   PdfDssDict lastDSSDictionary,
														   PdfDssDict currentDssDict) {
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
	 * This method verifies the validity of /ByteRange field against the extracted from /Contents field {@code cms}
	 * and the current pdf {@code document}
	 *
	 * @param byteRange {@link ByteRange} to be validated
	 * @param document {@link DSSDocument} current PDF document
	 * @param cms byte array representing the binaries extracted from /Contents field
	 * @return TRUE if the /ByteRange is valid, FALSE otherwise
	 */
	protected boolean validateByteRange(ByteRange byteRange, DSSDocument document, byte[] cms) {
		try {
			byteRange.validate();
			if (!isContentValueEqualsByteRangeExtraction(byteRange, document, cms)) {
				LOG.warn("Signature with the /ByteRange '{}' is invalid. SIWA detected!", byteRange);
				return false;
			}
			return true;

		} catch (Exception e) {
			String message = String.format("/ByteRange validation ended with error : %s. Reason : %s", byteRange, e.getMessage());
			if (LOG.isDebugEnabled()) {
				// Exception displays the (long) hex value
				LOG.error(message, e);
			} else {
				LOG.error(message);
			}
			return false;
		}
	}

	/**
	 * Checks if the of the value incorporated into /Contents matches the range defined in the {@code byteRange}
	 *
	 * NOTE: used for SIWA detection
	 *
	 * @param byteRange {@link ByteRange} defined within a signature
	 * @param document {@link DSSDocument} current PDF document
	 * @param cms binaries of the CMSSignedData extracted from /Contents field
	 * @return TRUE if the content value equals the byte range extraction, FALSE otherwise
	 * @throws IOException if an exception occurs on a signature value extraction
	 */
	private boolean isContentValueEqualsByteRangeExtraction(ByteRange byteRange, DSSDocument document, byte[] cms) throws IOException {
		byte[] cmsWithByteRange = PAdESUtils.getSignatureValue(document, byteRange);
		boolean match = Arrays.equals(cms, cmsWithByteRange);
		if (!match) {
			LOG.warn("The value extracted according to /ByteRange '{}' " +
					"does not match the signature present in /Contents field!", byteRange);
		}
		return match;
	}

	/**
	 * Extract the content before the signature value
	 *
	 * @param byteRange {@link ByteRange}
	 * @param signedContent byte array representing the signed content
	 * @return the first part of the byte range
	 */
	protected byte[] extractBeforeSignatureValue(ByteRange byteRange, byte[] signedContent) {
		if (!byteRange.isValid() || signedContent.length < byteRange.getFirstPartEnd()) {
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
			signatureFieldAnnotation = toPdfPageCoordinates(signatureFieldAnnotation, pageBox);

			assertSignatureFieldPositionValid(documentReader, signatureFieldAnnotation, fieldParameters.getPage());
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
		annotationBox = toPdfPageCoordinates(annotationBox, pageBox);

		assertSignatureFieldPositionValid(reader, annotationBox, parameters.getPage());
		return annotationBox;
	}

	/**
	 * This method verifies validity of the signature field box configuration
	 * calling the provided {@code pdfSignatureFieldPositionChecker}
	 *
	 * @param documentReader {@link PdfDocumentReader} document where the new signature field should be created
	 * @param annotationBox {@link AnnotationBox} defining position and dimensions of the new signature field
	 * @param pageNumber the number of a page where the new signature should be created
	 */
	protected void assertSignatureFieldPositionValid(PdfDocumentReader documentReader, AnnotationBox annotationBox,
													 int pageNumber) {
		pdfSignatureFieldPositionChecker.assertSignatureFieldPositionValid(documentReader, annotationBox, pageNumber);
	}

	/**
	 * This method transforms a {@code fieldAnnotationBox}'s positions and dimensions according to the given page
	 *
	 * @param fieldAnnotationBox {@link AnnotationBox} computed field of a signature
	 * @param pageBox {@link AnnotationBox} page's box
	 * @return {@link AnnotationBox}
	 */
	protected AnnotationBox toPdfPageCoordinates(AnnotationBox fieldAnnotationBox, AnnotationBox pageBox) {
		return fieldAnnotationBox.toPdfPageCoordinates(pageBox.getHeight());
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

	private PdfModificationDetection getModificationDetection(PdfDocumentReader finalRevisionReader,
															  DSSDocument originalDocument, String pwd) throws IOException {
		try (PdfDocumentReader signedRevisionReader = loadPdfDocumentReader(originalDocument , pwd)) {
			PdfModificationDetection pdfModificationDetection = new PdfModificationDetection();
			pdfModificationDetection.setAnnotationOverlaps(
					pdfDifferencesFinder.getAnnotationOverlaps(finalRevisionReader));
			pdfModificationDetection.setPageDifferences(
					pdfDifferencesFinder.getPagesDifferences(signedRevisionReader, finalRevisionReader));
			pdfModificationDetection.setVisualDifferences(
					getVisualDifferences(signedRevisionReader, finalRevisionReader));
			pdfModificationDetection.setObjectModifications(
					pdfObjectModificationsFinder.find(signedRevisionReader, finalRevisionReader));
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
	 */
	protected List<PdfModification> getVisualDifferences(final PdfDocumentReader signedRevisionReader,
														 final PdfDocumentReader finalRevisionReader) {
		return pdfDifferencesFinder.getVisualDifferences(signedRevisionReader, finalRevisionReader);
	}

	/**
	 * This method verifies the PDF permissions dictionaries
	 *
	 * @param documentReader {@link PdfDocumentReader} document to be checked
	 * @param fieldParameters {@link SignatureFieldParameters} identifying a new signature field configuration
	 */
	protected void checkPdfPermissions(PdfDocumentReader documentReader, SignatureFieldParameters fieldParameters) {
		pdfPermissionsChecker.checkDocumentPermissions(documentReader, fieldParameters);
		if (!isDocumentTimestampLayer()) {
			pdfPermissionsChecker.checkSignatureRestrictionDictionaries(documentReader, fieldParameters);
		}
	}

}
