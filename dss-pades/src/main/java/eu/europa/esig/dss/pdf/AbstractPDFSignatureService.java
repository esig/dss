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
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.exception.InvalidPasswordException;
import eu.europa.esig.dss.pades.validation.PdfModification;
import eu.europa.esig.dss.pades.validation.PdfModificationDetection;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pdf.visible.SignatureDrawer;
import eu.europa.esig.dss.pdf.visible.SignatureDrawerFactory;
import eu.europa.esig.dss.pdf.visible.SignatureFieldBoxBuilder;
import eu.europa.esig.dss.pdf.visible.VisualSignatureFieldAppearance;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ByteRange;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
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
	 * This variable set the behavior to follow in case of overlapping a new
	 * signature field with existing annotations.
	 * 
	 * Default : ExceptionOnStatusAlert - throw the exception
	 */
	private StatusAlert alertOnSignatureFieldOverlap = new ExceptionOnStatusAlert();

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
	 *                               DocumentTypestamp or Signature signature layer
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
			throw new DSSException("SignatureDrawer shall be defined for the used SignatureDrawerFactory!");
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
	 * This method checks if the document is not encrypted or with limited edition
	 * rights
	 * 
	 * @param toSignDocument {@link DSSDocument} the document which will be modified
	 * @param pwd            {@link String} password protection phrase used to
	 *                       encrypt the document
	 */
	protected abstract void checkDocumentPermissions(final DSSDocument toSignDocument, final String pwd);

	@Override
	public List<PdfRevision> getRevisions(final DSSDocument document, final String pwd) {
		List<PdfRevision> result = new ArrayList<>();
		try (PdfDocumentReader reader = loadPdfDocumentReader(document, pwd)) {

			final PdfDssDict dssDictionary = reader.getDSSDictionary();
			boolean mainDssDictionaryAdded = false;

			Map<PdfSignatureDictionary, List<String>> sigDictionaries = reader.extractSigDictionaries();
			sigDictionaries = sortSignatureDictionaries(sigDictionaries); // sort from the latest revision to the first

			for (Map.Entry<PdfSignatureDictionary, List<String>> sigDictEntry : sigDictionaries.entrySet()) {
				PdfSignatureDictionary signatureDictionary = sigDictEntry.getKey();
				List<String> fieldNames = sigDictEntry.getValue();
				try {
					LOG.info("Signature field name: {}", fieldNames);

					final ByteRange byteRange = signatureDictionary.getByteRange();
					byteRange.validate();

					final byte[] cms = signatureDictionary.getContents();
					byte[] signedContent = DSSUtils.EMPTY_BYTE_ARRAY;
					if (!isContentValueEqualsByteRangeExtraction(document, byteRange, cms, fieldNames)) {
						LOG.warn("Signature {} is skipped. SIWA detected !", fieldNames);
					} else {
						signedContent = PAdESUtils.getSignedContent(document, byteRange);
					}

					boolean signatureCoversWholeDocument = reader.isSignatureCoversWholeDocument(signatureDictionary);

					PdfDssDict previousRevisionDssDict = null;
					// LT or LTA
					if (dssDictionary != null) {
						// obtain covered DSS dictionary if already exist
						previousRevisionDssDict = getDSSDictionaryPresentInRevision(
								extractBeforeSignatureValue(byteRange, signedContent), pwd);
					}

					PdfCMSRevision newRevision = null;

					if (isDocTimestamp(signatureDictionary)) {
						newRevision = new PdfDocTimestampRevision(signatureDictionary, fieldNames, signedContent,
								signatureCoversWholeDocument);

					} else if (isSignature(signatureDictionary)) {
						// signature contains all dss dictionaries present after
						newRevision = new PdfSignatureRevision(signatureDictionary, dssDictionary, fieldNames,
								signedContent, signatureCoversWholeDocument);

					} else {
						LOG.warn("The entry {} is skipped. A signature dictionary entry with a type '{}' " +
										"and subFilter '{}' is not acceptable configuration!", fieldNames,
								signatureDictionary.getType(), signatureDictionary.getSubFilter());

					}

					boolean dssDictionaryUpdated = previousRevisionDssDict != null
							&& !previousRevisionDssDict.equals(dssDictionary);

					// add the main dss dictionary as the first revision
					if (dssDictionaryUpdated && !mainDssDictionaryAdded) {
						result.add(new PdfDocDssRevision(dssDictionary));
					}
					mainDssDictionaryAdded = true;

					// add signature/ timestamp revision
					if (newRevision != null) {
						newRevision.setModificationDetection(getPdfModificationDetection(reader, signedContent, pwd));
						result.add(newRevision);
					}

					// add a previous DSS revision
					if (previousRevisionDssDict != null) {
						result.add(new PdfDocDssRevision(previousRevisionDssDict));
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
		return result;
	}

	@Override
	public DSSDocument addDssDictionary(DSSDocument document, List<DSSDictionaryCallback> callbacks) {
		return addDssDictionary(document, callbacks, null);
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
	private Map<PdfSignatureDictionary, List<String>> sortSignatureDictionaries(
			Map<PdfSignatureDictionary, List<String>> pdfSignatureDictionary) {
		return pdfSignatureDictionary.entrySet().stream()
				.sorted(Map.Entry
						.<PdfSignatureDictionary, List<String>>comparingByKey(new PdfSignatureDictionaryComparator())
						.reversed())
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (oldValue, newValue) -> oldValue,
						LinkedHashMap::new));
	}

	private PdfDssDict getDSSDictionaryPresentInRevision(final byte[] originalBytes, final String pwd) {
		try (PdfDocumentReader reader = loadPdfDocumentReader(originalBytes, pwd)) {
			return reader.getDSSDictionary();
		} catch (Exception e) {
			LOG.debug("Cannot extract DSS dictionary from the previous revision : {}", e.getMessage(), e);
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
	 * @param signatureFieldNames a list of {@link String}
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
				LOG.debug(message, e);
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
		final byte[] result = new byte[length];
		System.arraycopy(signedContent, 0, result, 0, length);
		return result;
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
	 * This method builds a Map of known Objects (extracted from previous DSS
	 * Dictionaries). This map will be used to avoid duplicate the same objects
	 * between layers.
	 * 
	 * @param callbacks a list of {@link DSSDictionaryCallback}s
	 * @return a map of built objects and their ids
	 */
	protected Map<String, Long> buildKnownObjects(List<DSSDictionaryCallback> callbacks) {
		Map<String, Long> result = new HashMap<>();
		for (DSSDictionaryCallback callback : callbacks) {

			Map<Long, CertificateToken> storedCertificates = callback.getStoredCertificates();
			for (Entry<Long, CertificateToken> certEntry : storedCertificates.entrySet()) {
				String tokenKey = getTokenDigest(certEntry.getValue());
				if (!result.containsKey(tokenKey)) { // keeps the really first occurrence
					result.put(tokenKey, certEntry.getKey());
				}
			}

			Map<Long, BasicOCSPResp> storedOcspResps = callback.getStoredOcspResps();
			for (Entry<Long, BasicOCSPResp> ocspEntry : storedOcspResps.entrySet()) {
				final OCSPResp ocspResp = DSSRevocationUtils.fromBasicToResp(ocspEntry.getValue());
				String tokenKey = Utils
						.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, DSSRevocationUtils.getEncoded(ocspResp)));
				if (!result.containsKey(tokenKey)) { // keeps the really first occurrence
					result.put(tokenKey, ocspEntry.getKey());
				}
			}

			Map<Long, CRLBinary> storedCrls = callback.getStoredCrls();
			for (Entry<Long, CRLBinary> crlEntry : storedCrls.entrySet()) {
				String tokenKey = Utils
						.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, crlEntry.getValue().getBinaries()));
				if (!result.containsKey(tokenKey)) { // keeps the really first occurrence
					result.put(tokenKey, crlEntry.getKey());
				}
			}
		}
		return result;
	}

	/**
	 * Gets SHA-256 digest of the token
	 *
	 * @param token {@link Token}
	 * @return {@link String} base64 encoded SHA-256 digest
	 */
	protected String getTokenDigest(Token token) {
		return Utils.toBase64(token.getDigest(DigestAlgorithm.SHA256));
	}

	/**
	 * Checks validity of the SignatureField position
	 * 
	 * @param signatureDrawer {@link SignatureDrawer}
	 * @param documentReader  {@link PdfDocumentReader}
	 * @param fieldParameters {@link SignatureFieldParameters}
	 * @throws IOException if an exception occurs
	 */
	protected void checkVisibleSignatureFieldBoxPosition(SignatureDrawer signatureDrawer,
			PdfDocumentReader documentReader, SignatureFieldParameters fieldParameters) throws IOException {
		AnnotationBox signatureFieldAnnotation = buildSignatureFieldBox(signatureDrawer);
		if (signatureFieldAnnotation != null) {
			AnnotationBox pageBox = documentReader.getPageBox(fieldParameters.getPage());
			signatureFieldAnnotation = signatureFieldAnnotation.toPdfPageCoordinates(pageBox.getHeight());

			checkSignatureFieldBoxOverlap(documentReader, signatureFieldAnnotation, fieldParameters.getPage());
		}
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
	 * given page
	 * 
	 * @param reader     {@link PdfDocumentReader} to be validated
	 * @param parameters {@link SignatureFieldParameters}
	 * @return {@link AnnotationBox} computed signature field box
	 * @throws IOException if an exception occurs
	 */
	protected AnnotationBox checkVisibleSignatureFieldBoxPosition(final PdfDocumentReader reader,
			SignatureFieldParameters parameters) throws IOException {
		AnnotationBox annotationBox = new AnnotationBox(parameters);
		AnnotationBox pageBox = reader.getPageBox(parameters.getPage());
		annotationBox = annotationBox.toPdfPageCoordinates(pageBox.getHeight());

		checkSignatureFieldBoxOverlap(reader, annotationBox, parameters.getPage());

		return annotationBox;
	}

	private void checkSignatureFieldBoxOverlap(final PdfDocumentReader reader, final AnnotationBox signatureFieldBox,
			int page) throws IOException {
		List<PdfAnnotation> pdfAnnotations = reader.getPdfAnnotations(page);
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
	 * Proceeds PDF modification detection
	 * 
	 * @param finalRevisionReader {@link PdfDocumentReader} the reader for the final
	 *                            PDF content
	 * @param signedContent       a byte array representing a signed revision
	 *                            content
	 * @param pwd                 {@link String} password protection
	 * @return {@link PdfModificationDetection}
	 */
	protected PdfModificationDetection getPdfModificationDetection(final PdfDocumentReader finalRevisionReader,
			byte[] signedContent, String pwd) {
		try (PdfDocumentReader signedRevisionReader = loadPdfDocumentReader(new InMemoryDocument(signedContent), pwd)) {
			PdfModificationDetectionImpl pdfModificationDetection = new PdfModificationDetectionImpl();

			pdfModificationDetection
					.setAnnotationOverlaps(PdfModificationDetectionUtils.getAnnotationOverlaps(finalRevisionReader));
			pdfModificationDetection.setPageDifferences(
					PdfModificationDetectionUtils.getPagesDifferences(signedRevisionReader, finalRevisionReader));
			pdfModificationDetection
					.setVisualDifferences(getVisualDifferences(signedRevisionReader, finalRevisionReader));

			return pdfModificationDetection;

		} catch (Exception e) {
			String errorMessage = "Unable to proceed PDF modification detection. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.error(errorMessage, e.getMessage(), e);
			} else {
				LOG.error(errorMessage, e.getMessage());
			}
		}

		return null;
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

}
