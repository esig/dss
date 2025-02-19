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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
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
import eu.europa.esig.dss.pades.validation.PdfByteRangeDocument;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.PdfSignatureField;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pades.validation.dss.PdfCompositeDssDictionary;
import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder;
import eu.europa.esig.dss.pdf.modifications.PdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.PdfModification;
import eu.europa.esig.dss.pdf.modifications.PdfModificationDetection;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModificationsFinder;
import eu.europa.esig.dss.pdf.visible.ImageRotationUtils;
import eu.europa.esig.dss.pdf.visible.SignatureDrawer;
import eu.europa.esig.dss.pdf.visible.SignatureDrawerFactory;
import eu.europa.esig.dss.pdf.visible.SignatureFieldBoxBuilder;
import eu.europa.esig.dss.pdf.visible.VisualSignatureFieldAppearance;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandler;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
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
	 * Used to specify load mode of the PDF document
	 */
	protected PdfMemoryUsageSetting pdfMemoryUsageSetting = PAdESUtils.DEFAULT_PDF_MEMORY_USAGE_SETTING;

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
	
	@Override
	public void setPdfMemoryUsageSetting(PdfMemoryUsageSetting pdfMemoryUsageSetting) {
		Objects.requireNonNull(pdfMemoryUsageSetting, "PdfMemoryUsageSetting cannot be null!");
		this.pdfMemoryUsageSetting = pdfMemoryUsageSetting;
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
	public DSSMessageDigest messageDigest(DSSDocument toSignDocument, PAdESCommonParameters parameters) {
		Objects.requireNonNull(toSignDocument, "DSSDocument shall be provided!");
		Objects.requireNonNull(parameters, "PAdESCommonParameters cannot be null!");

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
		Objects.requireNonNull(toSignDocument, "DSSDocument shall be provided!");
		Objects.requireNonNull(cmsSignedData, "CMSSignedData cannot be null!");
		Objects.requireNonNull(parameters, "PAdESCommonParameters cannot be null!");

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

	/**
	 * This method ensures the PDF document structure is correct for inclusion of
	 * specific digital signature's functionalities
	 *
	 * @param documentReader {@link PdfDocumentReader} to be extended
	 * @param parameters {@link PAdESCommonParameters}
	 */
	protected void digitalSignatureEnhancement(PdfDocumentReader documentReader, PAdESCommonParameters parameters) {
		if (isDocumentTimestampLayer()) {
			ensureESICDeveloperExtension1(documentReader);
		}
		if (isCAdESDetached(parameters)) {
			ensureESICDeveloperExtension2(documentReader);
		}
		if (isISO_32001(parameters)) {
			ensureISO_32001DeveloperExtension(documentReader);
		}
		if (isISO_32002(parameters)) {
			ensureISO_32002DeveloperExtension(documentReader);
		}
	}

	/**
	 * This method verifies presence of the ESIC developer extension with level 1 in the PDF document.
	 * Creates one, when not present.
	 *
	 * @param documentReader {@link PdfDocumentReader}
	 */
	protected void ensureESICDeveloperExtension1(PdfDocumentReader documentReader) {
		// standard says the /BaseVersion shall be less than or equal to both the document header and catalog version
		// skip adding the extension when document's version is lower
		if (documentReader.getPdfHeaderVersion() < 1.7f || documentReader.getVersion() < 1.7f) {
			return;
		}
		// Skip inclusion of the dictionary, as the properties are already defined in PDF 2.0 (ISO 32000-2:2020)
		if (documentReader.getVersion() >= 2.0f) {
			return;
		}
		final PdfDict esicExtension = createDeveloperExtensionDict(documentReader,
				"1.7", 1, null, null, null);
		final PdfDict adbeExtension = createDeveloperExtensionDict(documentReader,
				"1.7", 8, null, null, null);
		if (!isDeveloperExtensionPresent(documentReader, "ESIC", esicExtension) &&
				!isDeveloperExtensionPresent(documentReader, "ADBE", adbeExtension)) {
			addDeveloperExtension(documentReader, "ADBE", adbeExtension);
		}
	}

	/**
	 * This method verifies presence of the ESIC developer extension with level 2 in the PDF document.
	 * Creates one, when not present.
	 *
	 * @param documentReader {@link PdfDocumentReader}
	 */
	protected void ensureESICDeveloperExtension2(PdfDocumentReader documentReader) {
		if (documentReader.getPdfHeaderVersion() < 1.7f || documentReader.getVersion() < 1.7f) {
			return;
		}
		// Skip inclusion of the dictionary, as the properties are already defined in PDF 2.0 (ISO 32000-2:2020)
		if (documentReader.getVersion() >= 2.0f) {
			return;
		}
		final PdfDict esicExtension = createDeveloperExtensionDict(documentReader,
				"1.7", 2, null, null, null);
		final PdfDict adbeExtension = createDeveloperExtensionDict(documentReader,
				"1.7", 8, null, null, null);
		if (!isDeveloperExtensionPresent(documentReader, "ESIC", esicExtension) &&
				!isDeveloperExtensionPresent(documentReader, "ADBE", adbeExtension)) {
			addDeveloperExtension(documentReader, "ADBE", adbeExtension);
		}
	}

	/**
	 * This method verifies presence of the ISO 32001 developer extension in the PDF document.
	 * Creates one, when not present.
	 *
	 * @param documentReader {@link PdfDocumentReader}
	 */
	protected void ensureISO_32001DeveloperExtension(PdfDocumentReader documentReader) {
		if (documentReader.getPdfHeaderVersion() < 2.0f || documentReader.getVersion() < 2.0f) {
			return;
		}
		final PdfDict developerExtension = createDeveloperExtensionDict(documentReader,
				"2.0", 32001, ":2022", "DeveloperExtensions", "https://www.iso.org/standard/45874.html");
		if (!isDeveloperExtensionPresent(documentReader, "ISO_", developerExtension)) {
			addDeveloperExtension(documentReader, "ISO_", developerExtension);
		}
	}

	/**
	 * This method verifies presence of the ISO 32002 developer extension in the PDF document.
	 * Creates one, when not present.
	 *
	 * @param documentReader {@link PdfDocumentReader}
	 */
	protected void ensureISO_32002DeveloperExtension(PdfDocumentReader documentReader) {
		if (documentReader.getPdfHeaderVersion() < 2.0f || documentReader.getVersion() < 2.0f) {
			return;
		}
		final PdfDict developerExtension = createDeveloperExtensionDict(documentReader,
				"2.0", 32002, ":2022", "DeveloperExtensions", "https://www.iso.org/standard/45875.html");
		if (!isDeveloperExtensionPresent(documentReader, "ISO_", developerExtension)) {
			addDeveloperExtension(documentReader, "ISO_", developerExtension);
		}
	}

	/**
	 * Creates a new developer extension dictionary with the given configuration
	 *
	 * @param documentReader {@link PdfDocumentReader}
	 * @param baseVersion {@link String}
	 * @param extensionLevel {@link String}
	 * @param extensionRevision {@link String}
	 * @param type {@link String}
	 * @param url {@link String}
	 * @return {@link PdfDict}
	 */
	protected PdfDict createDeveloperExtensionDict(PdfDocumentReader documentReader, String baseVersion, Integer extensionLevel,
												   String extensionRevision, String type, String url) {
		final PdfDict pdfDict = documentReader.createPdfDict();
		if (baseVersion != null) {
			pdfDict.setNameValue(PAdESConstants.BASE_VERSION_NAME, baseVersion);
		}
		if (extensionLevel != null) {
			pdfDict.setIntegerValue(PAdESConstants.EXTENSION_LEVEL_NAME, extensionLevel);
		}
		if (extensionRevision != null) {
			pdfDict.setStringValue(PAdESConstants.EXTENSION_REVISION_NAME, extensionRevision);
		}
		if (type != null) {
			pdfDict.setNameValue(PAdESConstants.TYPE_NAME, type);
		}
		if (url != null) {
			pdfDict.setStringValue(PAdESConstants.URL_NAME, url);
		}
		return pdfDict;
	}

	/**
	 * Verifies if the signature is created with a use of "ETSI.CAdES.detached" SubFilter
	 *
	 * @param parameters {@link PAdESCommonParameters}
	 * @return TRUE if the "ETSI.CAdES.detached" SubFilter is used, FALSE otherwise
	 */
	protected boolean isCAdESDetached(PAdESCommonParameters parameters) {
		return PAdESConstants.SIGNATURE_DEFAULT_SUBFILTER.equals(parameters.getSubFilter());
	}

	/**
	 * Verifies if the ISO_ profile for 32001 shall be activated
	 *
	 * @param parameters {@link PAdESCommonParameters}
	 * @return TRUE if the ISO_ developer extension shall be included, FALSE otherwise
	 */
	protected boolean isISO_32001(PAdESCommonParameters parameters) {
		return (PAdESConstants.SIGNATURE_PKCS7_SUBFILTER.equals(parameters.getSubFilter()) ||
				PAdESConstants.SIGNATURE_DEFAULT_SUBFILTER.equals(parameters.getSubFilter()) ||
				PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER.equals(parameters.getSubFilter())) &&
				(DigestAlgorithm.SHA3_256 == parameters.getDigestAlgorithm() || DigestAlgorithm.SHA3_384 == parameters.getDigestAlgorithm() ||
				DigestAlgorithm.SHA3_512 == parameters.getDigestAlgorithm() || DigestAlgorithm.SHAKE256 == parameters.getDigestAlgorithm());
	}

	/**
	 * Verifies if the ISO_ profile for 32002 shall be activated
	 *
	 * @param parameters {@link PAdESCommonParameters}
	 * @return TRUE if the ISO_ developer extension shall be included, FALSE otherwise
	 */
	protected boolean isISO_32002(PAdESCommonParameters parameters) {
		// TODO : add support of ECDSA elliptic curves
		// Note: ISO 32002 mistakenly refers id-shake256 instead of id-shake256-len digest algorithm for Ed448 algorithm.
		// See {@link https://github.com/pdf-association/pdf-issues/issues/404} for more information.
		// However, the developer extension for id-shake256-len is not enforced in order to stay compliant with the current version of ISO 32002.
		return (PAdESConstants.SIGNATURE_PKCS7_SUBFILTER.equals(parameters.getSubFilter()) ||
				PAdESConstants.SIGNATURE_DEFAULT_SUBFILTER.equals(parameters.getSubFilter()) ||
				PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER.equals(parameters.getSubFilter())) &&
				(EncryptionAlgorithm.EDDSA == parameters.getEncryptionAlgorithm() &&
						(DigestAlgorithm.SHA512 == parameters.getDigestAlgorithm() || DigestAlgorithm.SHAKE256 == parameters.getDigestAlgorithm())
				);
	}

	/**
	 * Verifies whether the specified developer extension is present in the document's catalog.
	 * The extension shall fully match the defined parameters.
	 *
	 * @param documentReader {@link PdfDocumentReader}
	 * @param prefix {@link String}
	 * @param developerExtension {@link PdfDict}
	 * @return TRUE if the extension is present, FALSE otherwise
	 */
	protected boolean isDeveloperExtensionPresent(PdfDocumentReader documentReader, String prefix, PdfDict developerExtension) {
		PdfDict catalogDict = documentReader.getCatalogDictionary();
		PdfDict extensionsDict = catalogDict.getAsDict(PAdESConstants.EXTENSIONS_NAME);
		if (extensionsDict != null) {
			// can be array or dictionary
			if (extensionsDict.getAsArray(prefix) != null) {
				PdfArray extensionDictArray = extensionsDict.getAsArray(prefix);
				for (int i = 0; i < extensionDictArray.size(); i++) {
					PdfDict extensionDict = extensionDictArray.getAsDict(i);
					if (extensionDict != null && extensionDict.match(developerExtension)) {
						return true;
					}
				}

			} else if (extensionsDict.getAsDict(prefix) != null && extensionsDict.getAsDict(prefix).match(developerExtension)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Adds a new developer extension defined in {@code developerExtension} dictionary
	 *
	 * @param documentReader {@link PdfDocumentReader}
	 * @param prefix {@link String}
	 * @param developerExtension {@link PdfDict}
	 */
	protected void addDeveloperExtension(PdfDocumentReader documentReader, String prefix, PdfDict developerExtension) {
		final PdfDict catalogDict = documentReader.getCatalogDictionary();

		PdfDict extensionsDict = catalogDict.getAsDict(PAdESConstants.EXTENSIONS_NAME);
		if (extensionsDict == null) {
			extensionsDict = documentReader.createPdfDict();
			extensionsDict.setDirect(true);
			catalogDict.setPdfObjectValue(PAdESConstants.EXTENSIONS_NAME, extensionsDict);
		}

		PdfArray extensionDictArray = extensionsDict.getAsArray(prefix);
		PdfDict existingDictionary = extensionsDict.getAsDict(prefix);
		if (existingDictionary != null) {
			extensionDictArray = documentReader.createPdfArray();
			existingDictionary.setDirect(false);
			extensionDictArray.addObject(existingDictionary);
			extensionsDict.setPdfObjectValue(prefix, extensionDictArray);
		}
		if (extensionDictArray != null) {
			extensionDictArray.addObject(developerExtension);
		} else {
			// add directly to ensure better compatibility (PDF 1.7)
			developerExtension.setDirect(true);
			extensionsDict.setPdfObjectValue(prefix, developerExtension);
		}
	}

	@Override
	public List<PdfRevision> getRevisions(final DSSDocument document, final char[] pwd) {
		Objects.requireNonNull(document, "DSSDocument shall be provided!");

		final List<PdfRevision> revisions = new ArrayList<>();
		final List<PdfByteRangeDocument> revisionDocuments = PAdESUtils.extractRevisions(document);

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

					DSSDocument signedContent = null;
					if (byteRange.isValid()) {
						signedContent = new PdfByteRangeDocument(document, byteRange);
						if (!isSignedContentComplete(byteRange, signedContent)) {
							byteRange.setValid(false);
						}
					}

					if (!byteRange.isValid()) {
						signedContent = InMemoryDocument.createEmptyDocument();
						LOG.warn("The signature '{}' has an invalid /ByteRange! " +
								"The validation will result to a broken signature.", fieldNames);
					}

					final boolean signatureCoversWholeDocument = reader.isSignatureCoversWholeDocument(signatureDictionary);

					final DSSDocument revisionContent = PAdESUtils.getRevisionContent(document, byteRange);
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

					final DSSDocument previousRevision = PAdESUtils.getPreviousRevision(byteRange, revisionDocuments);
					PdfCMSRevision newRevision = null;
					if (isDocTimestamp(signatureDictionary)) {
						newRevision = new PdfDocTimestampRevision(signatureDictionary, fields, signedContent,
								previousRevision, signatureCoversWholeDocument);

					} else if (isSignature(signatureDictionary)) {
						// signature contains all dss dictionaries present after
						newRevision = new PdfSignatureRevision(signatureDictionary, compositeDssDictionary,
								containsDSSRevisions(revisions) ? dssDictionary : null, fields, signedContent,
								previousRevision, signatureCoversWholeDocument);

					} else {
						LOG.warn("The entry {} is skipped. A signature dictionary entry with a type '{}' " +
										"and subFilter '{}' is not acceptable configuration!", fieldNames,
								signatureDictionary.getType(), signatureDictionary.getSubFilter());

					}

					// add signature/timestamp revision
					if (newRevision != null) {
						revisions.add(newRevision);
					}

					try (PdfDocumentReader revisionReader = loadPdfDocumentReader(previousRevision, pwd)) {

						// checks if there is a previous update of the DSS dictionary and creates a new revision if needed
						lastDSSDictionary = getPreviousDssDictAndUpdateIfNeeded(revisions, compositeDssDictionary,
								lastDSSDictionary, revisionReader.getDSSDictionary());

					} catch (Exception e) {
						// do nothing
					}


				} catch (Exception e) {
					String errorMessage = "Unable to parse signature {} . Reason : {}";
					if (LOG.isDebugEnabled()) {
						LOG.warn(errorMessage, fieldNames, e.getMessage(), e);
					} else {
						LOG.warn(errorMessage, fieldNames, e.getMessage());
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
	public DSSDocument addDssDictionary(final DSSDocument document, final PdfValidationDataContainer validationDataForInclusion,
										final char[] pwd) {
		return addDssDictionary(document, validationDataForInclusion, pwd, false);
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
	 * @param passwordProtection the password used to protect the document
	 * @return {@link PdfDocumentReader}
	 * @throws IOException              in case of loading error
	 * @throws InvalidPasswordException if the password is not provided or invalid
	 *                                  for a protected document
	 */
	protected abstract PdfDocumentReader loadPdfDocumentReader(DSSDocument dssDocument, char[] passwordProtection)
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

	private boolean containsDSSRevisions(List<PdfRevision> revisions) {
		return revisions.stream().anyMatch(PdfDocDssRevision.class::isInstance);
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
				LOG.warn(message, e);
			} else {
				LOG.warn(message);
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
	 */
	private boolean isContentValueEqualsByteRangeExtraction(ByteRange byteRange, DSSDocument document, byte[] cms) {
		byte[] cmsWithByteRange = PAdESUtils.getSignatureValue(document, byteRange);
		boolean match = Arrays.equals(cms, cmsWithByteRange);
		if (!match) {
			LOG.warn("The value extracted according to /ByteRange '{}' " +
					"does not match the signature present in /Contents field!", byteRange);
		}
		return match;
	}

	/**
	 * This method verifies whether the extracted signed content corresponds to the byte range
	 *
	 * @param byteRange {@link ByteRange} of the signature
	 * @param signedContent {@link DSSDocument} the corresponding extracted signed content
	 * @return TRUE if the extracted signed content is complete and consistent to the ByteRange, FALSE otherwise
	 */
	private boolean isSignedContentComplete(ByteRange byteRange, DSSDocument signedContent) {
		int expectedSignedContentLength = (byteRange.getFirstPartEnd() - byteRange.getFirstPartStart()) + byteRange.getSecondPartEnd();
		long signedContentLength = DSSUtils.getFileByteSize(signedContent);
		if (expectedSignedContentLength != signedContentLength) {
			LOG.warn("The length of the extracted signed content '{}' does not correspond to the content length " +
					"defined by the ByteRange {} : {}!", signedContentLength, byteRange, expectedSignedContentLength);
			return false;
		}
		return true;
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
		int pageRotation = reader.getPageRotation(parameters.getPage());
		int globalRotation = ImageRotationUtils.getRotation(parameters.getRotation(), pageRotation);

		AnnotationBox originalPageBox = reader.getPageBox(parameters.getPage());
		AnnotationBox pageBox = originalPageBox;
		AnnotationBox annotationBox = new AnnotationBox(parameters);
		if (ImageRotationUtils.isSwapOfDimensionsRequired(globalRotation)) {
			pageBox = ImageRotationUtils.swapDimensions(pageBox);
		}

		annotationBox = ImageRotationUtils.rotateRelativelyWrappingBox(annotationBox, pageBox, 360 - globalRotation);

		annotationBox = toPdfPageCoordinates(annotationBox, originalPageBox);

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
	public void analyzePdfModifications(DSSDocument document, List<AdvancedSignature> signatures, char[] pwd) {
		if (Utils.isCollectionEmpty(signatures)) {
			return;
		}

		try (PdfDocumentReader finalRevisionReader = loadPdfDocumentReader(document, pwd)) {
			for (AdvancedSignature signature : signatures) {
				PAdESSignature padesSignature = (PAdESSignature) signature;
				analyzePdfModifications(document, padesSignature.getPdfRevision(), finalRevisionReader, pwd);
			}
			for (TimestampToken timestampToken : getUniqueTimestamps(signatures)) {
				PdfTimestampToken pdfTimestampToken = (PdfTimestampToken) timestampToken;
				analyzePdfModifications(document, pdfTimestampToken.getPdfRevision(), finalRevisionReader, pwd);
			}

		} catch (Exception e) {
			String errorMessage = "Unable to proceed PDF modification detection. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, e.getMessage());
			}
		}
	}

	private List<TimestampToken> getUniqueTimestamps(List<AdvancedSignature> signatures) {
		List<TimestampToken> timestampTokens = new ArrayList<>();
		for (AdvancedSignature signature : signatures) {
			timestampTokens.addAll(signature.getDocumentTimestamps());
		}
		return timestampTokens;
	}

	@Override
	public void analyzeTimestampPdfModifications(DSSDocument document, List<TimestampToken> timestamps, char[] pwd) {
		if (Utils.isCollectionEmpty(timestamps)) {
			return;
		}

		try (PdfDocumentReader finalRevisionReader = loadPdfDocumentReader(document, pwd)) {
			for (TimestampToken timestampToken : timestamps) {
				if (timestampToken instanceof PdfTimestampToken) {
					PdfTimestampToken pdfTimestampToken = (PdfTimestampToken) timestampToken;
					analyzePdfModifications(document, pdfTimestampToken.getPdfRevision(), finalRevisionReader, pwd);
				}
			}

		} catch (Exception e) {
			String errorMessage = "Unable to proceed PDF modification detection. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, e.getMessage());
			}
		}
	}

	/**
	 * This method performs a modification analysis for a single given {@code pdfRevision}
	 *
	 * @param document {@link DSSDocument} the validating document
	 * @param pdfRevision {@link PdfCMSRevision} signature revision to be validated
	 * @param finalRevisionReader {@link PdfDocumentReader} final document revision
	 * @param pwd char array representing the password string
	 * @throws IOException if an exception occurs while reading the PDF document
	 */
	protected void analyzePdfModifications(DSSDocument document, PdfCMSRevision pdfRevision,
										   PdfDocumentReader finalRevisionReader, char[] pwd) throws IOException {
		DSSDocument revisionContent = PAdESUtils.getRevisionContent(document, pdfRevision.getByteRange());
		pdfRevision.setModificationDetection(getModificationDetection(finalRevisionReader, revisionContent, pwd));
	}

	private PdfModificationDetection getModificationDetection(PdfDocumentReader finalRevisionReader,
															  DSSDocument originalDocument, char[] pwd) throws IOException {
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
