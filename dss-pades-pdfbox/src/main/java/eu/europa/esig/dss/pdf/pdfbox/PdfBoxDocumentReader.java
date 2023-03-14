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
package eu.europa.esig.dss.pdf.pdfbox;

import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESCommonParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.validation.ByteRange;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.PdfSignatureField;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfAnnotation;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfPermissionsChecker;
import eu.europa.esig.dss.pdf.PdfSigDictWrapper;
import eu.europa.esig.dss.pdf.SingleDssDict;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The PDFBox implementation of {@code PdfDocumentReader}
 *
 */
public class PdfBoxDocumentReader implements PdfDocumentReader {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxDocumentReader.class);

	/** The PDFBox implementation of the document */
	private final PDDocument pdDocument;

	/** The PDF document */
	private DSSDocument dssDocument;

	/** The map of signature dictionaries and corresponding signature fields */
	private Map<PdfSignatureDictionary, List<PdfSignatureField>> signatureDictionaryMap;

	/**
	 * Default constructor of the PDFBox implementation of the Reader
	 * 
	 * @param dssDocument               {@link DSSDocument} to read
	 * @throws IOException              if an exception occurs
	 * @throws eu.europa.esig.dss.pades.exception.InvalidPasswordException if the password is not provided or
	 *                                  invalid for a protected document
	 */
	public PdfBoxDocumentReader(DSSDocument dssDocument)
			throws IOException, eu.europa.esig.dss.pades.exception.InvalidPasswordException {
		this(dssDocument, null);
	}

	/**
	 * The PDFBox implementation of the Reader
	 * 
	 * @param dssDocument        {@link DSSDocument} to read
	 * @param passwordProtection {@link String} a password to open a protected document
	 * @throws IOException       if an exception occurs
	 * @throws eu.europa.esig.dss.pades.exception.InvalidPasswordException if the password is not provided or
	 *                           invalid for a protected document
	 */
	public PdfBoxDocumentReader(DSSDocument dssDocument, String passwordProtection)
			throws IOException, eu.europa.esig.dss.pades.exception.InvalidPasswordException {
		Objects.requireNonNull(dssDocument, "The document must be defined!");
		this.dssDocument = dssDocument;
		try (InputStream is = dssDocument.openStream()) {
			this.pdDocument = PDDocument.load(is, passwordProtection);
		} catch (InvalidPasswordException e) {
			throw new eu.europa.esig.dss.pades.exception.InvalidPasswordException(
					String.format("Encrypted document : %s", e.getMessage()));
		}
	}

	/**
	 * The PDFBox implementation of the Reader
	 * 
	 * @param binaries           a byte array of a PDF to read
	 * @param passwordProtection {@link String} a password to open a protected
	 *                           document
	 * @throws IOException       if an exception occurs
	 * @throws eu.europa.esig.dss.pades.exception.InvalidPasswordException if the password is not provided or
	 *                           invalid for a protected document
	 */
	public PdfBoxDocumentReader(byte[] binaries, String passwordProtection)
			throws IOException, eu.europa.esig.dss.pades.exception.InvalidPasswordException {
		Objects.requireNonNull(binaries, "The document binaries must be defined!");
		this.dssDocument = new InMemoryDocument(binaries);
		try {
			this.pdDocument = PDDocument.load(binaries, passwordProtection);
		} catch (InvalidPasswordException e) {
			throw new eu.europa.esig.dss.pades.exception.InvalidPasswordException(
					String.format("Encrypted document : %s", e.getMessage()));
		}
	}

	/**
	 * The constructor to directly instantiate the {@code PdfBoxDocumentReader}
	 * 
	 * @param pdDocument {@link PDDocument}
	 */
	public PdfBoxDocumentReader(final PDDocument pdDocument) {
		this.pdDocument = pdDocument;
	}

	/**
	 * Returns the current instance of {@code PDDocument}
	 *
	 * @return {@link PDDocument}
	 */
	public PDDocument getPDDocument() {
		return pdDocument;
	}

	@Override
	public PdfDssDict getDSSDictionary() {
		PdfDict catalog = new PdfBoxDict(pdDocument.getDocumentCatalog().getCOSObject(), pdDocument);
		return SingleDssDict.extract(catalog);
	}

	@Override
	public Map<PdfSignatureDictionary, List<PdfSignatureField>> extractSigDictionaries() throws IOException {
		if (signatureDictionaryMap == null) {
			signatureDictionaryMap = new LinkedHashMap<>();
			Map<Long, PdfSignatureDictionary> pdfObjectDictMap = new LinkedHashMap<>();

			final List<PDSignatureField> pdSignatureFields = pdDocument.getSignatureFields();
			if (Utils.isCollectionNotEmpty(pdSignatureFields)) {
				LOG.debug("{} signature(s) found", pdSignatureFields.size());

				for (PDSignatureField signatureField : pdSignatureFields) {
					final PdfBoxDict sigFieldDict = new PdfBoxDict(signatureField.getCOSObject(), pdDocument);
					final PdfSignatureField pdfSignatureField = new PdfSignatureField(sigFieldDict);

					COSObject sigDictObject = signatureField.getCOSObject().getCOSObject(COSName.V);
					if (sigDictObject == null || !(sigDictObject.getObject() instanceof COSDictionary)) {
						LOG.warn("Signature field with name '{}' does not contain a signature", pdfSignatureField.getFieldName());
						continue;
					}

					long sigDictNumber = sigDictObject.getObjectNumber();
					PdfSignatureDictionary signature = pdfObjectDictMap.get(sigDictNumber);
					if (signature == null) {
						try {
							PdfDict dictionary = new PdfBoxDict((COSDictionary) sigDictObject.getObject(), pdDocument);
							signature = new PdfSigDictWrapper(dictionary);
						} catch (Exception e) {
							LOG.warn("Unable to create a PdfSignatureDictionary for field with name '{}'",
									pdfSignatureField.getFieldName(), e);
							continue;
						}

						List<PdfSignatureField> fields = new ArrayList<>();
						fields.add(pdfSignatureField);
						signatureDictionaryMap.put(signature, fields);
						pdfObjectDictMap.put(sigDictNumber, signature);

					} else {
						List<PdfSignatureField> fieldList = signatureDictionaryMap.get(signature);
						fieldList.add(pdfSignatureField);
						LOG.warn("More than one field refers to the same signature dictionary: {}!", fieldList);

					}

				}
			}
		}
		return signatureDictionaryMap;
	}

	@Override
	public boolean isSignatureCoversWholeDocument(PdfSignatureDictionary signatureDictionary) {
		ByteRange byteRange = signatureDictionary.getByteRange();
		try (InputStream is = dssDocument.openStream()) {
			long originalBytesLength = Utils.getInputStreamSize(is);
			// /ByteRange [0 575649 632483 10206]
			long beforeSignatureLength = (long) byteRange.getFirstPartEnd() - byteRange.getFirstPartStart();
			long expectedCMSLength = (long) byteRange.getSecondPartStart() - byteRange.getFirstPartEnd()
					- byteRange.getFirstPartStart();
			long afterSignatureLength = byteRange.getSecondPartEnd();
			long totalCoveredByByteRange = beforeSignatureLength + expectedCMSLength + afterSignatureLength;

			return (originalBytesLength == totalCoveredByByteRange);
		} catch (IOException e) {
			LOG.warn("Cannot determine the original file size for the document. Reason : {}", e.getMessage());
			return false;
		}
	}

	@Override
	public void close() throws IOException {
		pdDocument.close();
	}

	@Override
	public int getNumberOfPages() {
		return pdDocument.getNumberOfPages();
	}

	@Override
	public AnnotationBox getPageBox(int page) {
		PDPage pdPage = getPDPage(page);
		PDRectangle mediaBox = pdPage.getMediaBox();
		return new AnnotationBox(mediaBox.getLowerLeftX(), mediaBox.getLowerLeftY(), mediaBox.getUpperRightX(),
				mediaBox.getUpperRightY());
	}

	@Override
	public int getPageRotation(int page) {
		PDPage pdPage = getPDPage(page);
		return pdPage.getRotation();
	}

	@Override
	public List<PdfAnnotation> getPdfAnnotations(int page) throws IOException {
		List<PdfAnnotation> annotations = new ArrayList<>();
		List<PDAnnotation> pdAnnotations = getPageAnnotations(page);
		for (PDAnnotation pdAnnotation : pdAnnotations) {
			PdfAnnotation pdfAnnotation = toPdfAnnotation(pdAnnotation);
			if (pdfAnnotation != null) {
				annotations.add(pdfAnnotation);
			}
		}
		return annotations;
	}

	private List<PDAnnotation> getPageAnnotations(int page) throws IOException {
		PDPage pdPage = getPDPage(page);
		return pdPage.getAnnotations();
	}

	/**
	 * Returns a {@code PDPage}
	 * 
	 * @param page number
	 * @return {@link PDPage}
	 */
	public PDPage getPDPage(int page) {
		return pdDocument.getPage(page - ImageUtils.DEFAULT_FIRST_PAGE);
	}

	private PdfAnnotation toPdfAnnotation(PDAnnotation pdAnnotation) {
		PDRectangle pdRect = pdAnnotation.getRectangle();
		if (pdRect != null) {
			AnnotationBox annotationBox = new AnnotationBox(pdRect.getLowerLeftX(), pdRect.getLowerLeftY(),
					pdRect.getUpperRightX(), pdRect.getUpperRightY());
			PdfAnnotation pdfAnnotation = new PdfAnnotation(annotationBox);
			pdfAnnotation.setName(getSignatureFieldName(pdAnnotation));
			return pdfAnnotation;
		}
		return null;
	}

	private String getSignatureFieldName(PDAnnotation pdAnnotation) {
		return pdAnnotation.getCOSObject().getString(COSName.T);
	}

	@Override
	public BufferedImage generateImageScreenshot(int page) throws IOException {
		PDFRenderer renderer = new PDFRenderer(pdDocument);
		return renderer.renderImage(page - ImageUtils.DEFAULT_FIRST_PAGE);
	}

	@Override
	public BufferedImage generateImageScreenshotWithoutAnnotations(int page, List<PdfAnnotation> annotations)
			throws IOException {
		List<PDAnnotation> pdAnnotations = getPageAnnotations(page);
		pdAnnotations = getMatchingPDAnnotations(pdAnnotations, annotations);
		List<PDAnnotation> hiddenList = changeVisibility(pdAnnotations, true);
		try {
			return generateImageScreenshot(page);
		} finally {
			// restore the original state
			changeVisibility(hiddenList, false);
		}
	}

	private List<PDAnnotation> getMatchingPDAnnotations(List<PDAnnotation> pdAnnotations, List<PdfAnnotation> annotationsToExtract) {
		List<PDAnnotation> result = new ArrayList<>();
		for (PDAnnotation pdAnnotation : pdAnnotations) {
			PdfAnnotation pdfAnnotation = toPdfAnnotation(pdAnnotation);
			if (annotationsToExtract.contains(pdfAnnotation)) {
				result.add(pdAnnotation);
			}
		}
		return result;
	}

	/**
	 * Changes a "Hidden" flag for provided {@code PDAnnotation}s according to the given boolean parameter
	 *
	 * @param pdAnnotations a list of {@link PDAnnotation}s
	 * @param hide if true - hides an annotation, if false - show the annotation
	 * @return a list of changed {@link PDAnnotation}s
	 */
	private List<PDAnnotation> changeVisibility(List<PDAnnotation> pdAnnotations, boolean hide) {
		List<PDAnnotation> modifiedList = new ArrayList<>();
		for (PDAnnotation pdAnnotation : pdAnnotations) {
			if (hide != pdAnnotation.isHidden()) {
				pdAnnotation.setHidden(hide);
				modifiedList.add(pdAnnotation);
			}
		}
		return modifiedList;
	}

	@Override
	public boolean isEncrypted() {
		return pdDocument.isEncrypted();
	}

	@Override
	public boolean isOpenWithOwnerAccess() {
		final AccessPermission accessPermission = getAccessPermission();
		return accessPermission.isOwnerPermission();
	}

	@Override
	public boolean canFillSignatureForm() {
		final AccessPermission accessPermission = getAccessPermission();
		return accessPermission.canModifyAnnotations() || accessPermission.canFillInForm();
	}

	@Override
	public boolean canCreateSignatureField() {
		final AccessPermission accessPermission = getAccessPermission();
		return accessPermission.canModify() && accessPermission.canModifyAnnotations();
	}

	private AccessPermission getAccessPermission() {
		return pdDocument.getCurrentAccessPermission();
	}

	@Override
	public CertificationPermission getCertificationPermission() {
		/*
		 * Origin: https://github.com/ETDA/PDFTimestamping/blob/master/src/main/java/SigUtils.java
		 */
		PDDocumentCatalog catalog = pdDocument.getDocumentCatalog();
		if (catalog != null) {
			COSBase base = catalog.getCOSObject().getDictionaryObject(COSName.PERMS);
			if (base instanceof COSDictionary) {
				COSDictionary permsDict = (COSDictionary) base;
				base = permsDict.getDictionaryObject(COSName.DOCMDP);
				if (base instanceof COSDictionary) {
					COSDictionary signatureDict = (COSDictionary) base;
					base = signatureDict.getDictionaryObject(COSName.REFERENCE);
					if (base instanceof COSArray) {
						COSArray refArray = (COSArray) base;
						for (int i = 0; i < refArray.size(); i++) {
							CertificationPermission certificationPermission = getPermissionFromReference(refArray.getObject(i));
							if (certificationPermission != null) {
								return certificationPermission;
							}
						}
					}
				}
			}
		}
		return null;
	}

	private CertificationPermission getPermissionFromReference(COSBase reference) {
		if (reference instanceof COSDictionary) {
			COSDictionary sigRefDict = (COSDictionary) reference;
			if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject(COSName.TRANSFORM_METHOD))) {
				COSBase transformParams = sigRefDict.getDictionaryObject(COSName.TRANSFORM_PARAMS);
				if (transformParams instanceof COSDictionary) {
					COSDictionary transformDict = (COSDictionary) transformParams;
					int accessPermissions = transformDict.getInt(COSName.P, 2);
					if (accessPermissions < 1 || accessPermissions > 3) {
						accessPermissions = 2;
					}
					return CertificationPermission.fromCode(accessPermissions);
				}
			}
		}
		return null;
	}

	@Override
	public boolean isUsageRightsSignaturePresent() {
		PDDocumentCatalog catalog = pdDocument.getDocumentCatalog();
		if (catalog != null) {
			COSBase base = catalog.getCOSObject().getDictionaryObject(COSName.PERMS);
			if (base instanceof COSDictionary) {
				COSDictionary permsDict = (COSDictionary) base;
				base = permsDict.getDictionaryObject(PAdESConstants.UR_NAME);
				if (base != null) {
					return true;
				}
				base = permsDict.getDictionaryObject(PAdESConstants.UR3_NAME);
				if (base != null) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public PdfDict getCatalogDictionary() {
		return new PdfBoxDict(pdDocument.getDocumentCatalog().getCOSObject(), pdDocument);
	}

	/**
	 * Computes a DocumentId in a deterministic way based on the given {@code parameters} and the document
	 *
	 * @param parameters {@link PAdESCommonParameters}
	 * @return deterministic identifier
	 */
	public long generateDocumentId(PAdESCommonParameters parameters) {
		/*
		 * Computation is according to "14.4 File identifiers"
		 */
		String deterministicId = parameters.getDeterministicId();
		if (dssDocument != null && dssDocument.getName() != null) {
			deterministicId = deterministicId + "-" + dssDocument.getName();
		}

		long documentId = dssDocument != null ? DSSUtils.getFileByteSize(dssDocument) : 0;
		// attach String to long value in a deterministic way
		for (int i = 0; i < deterministicId.length(); i++) {
			documentId += ((long) deterministicId.charAt(i) & 0xFF) << (8 * i);
		}
		return documentId;
	}

}
