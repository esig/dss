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
package eu.europa.esig.dss.pdf.openpdf;

import com.lowagie.text.Rectangle;
import com.lowagie.text.exceptions.BadPasswordException;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.AcroFields.Item;
import com.lowagie.text.pdf.ByteBuffer;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfIndirectReference;
import com.lowagie.text.pdf.PdfLiteral;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfNumber;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStream;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfWriter;
import com.lowagie.text.pdf.RandomAccessFileOrArray;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESCommonParameters;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.exception.InvalidPasswordException;
import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.PdfSignatureField;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.PdfAnnotation;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.pdf.PdfSigDictWrapper;
import eu.europa.esig.dss.pdf.SingleDssDict;
import eu.europa.esig.dss.pdf.visible.ImageRotationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The IText (OpenPdf) implementation of {@code PdfDocumentReader}
 *
 */
public class ITextDocumentReader implements PdfDocumentReader {

	private static final Logger LOG = LoggerFactory.getLogger(ITextDocumentReader.class);

	/** The PDF document reader */
	private final PdfReader pdfReader;

	/** The original PDF document */
	private DSSDocument dssDocument;

	/** The map of signature dictionaries and corresponding signature fields */
	private Map<PdfSignatureDictionary, List<PdfSignatureField>> signatureDictionaryMap;

	/**
	 * Default constructor of the OpenPDF implementation of the Reader
	 * 
	 * @param dssDocument {@link DSSDocument} to read
	 * @throws IOException if an exception occurs
	 * @throws InvalidPasswordException if the password is not provided or invalid for a protected document
	 */
	public ITextDocumentReader(DSSDocument dssDocument) throws IOException, InvalidPasswordException {
		this(dssDocument, null);
	}

	/**
	 * The OpenPDF implementation of the Reader to read a password-protected document
	 *
	 * @param dssDocument {@link DSSDocument} to read
	 * @param passwordProtection binaries of a password to open a protected document
	 * @throws IOException if an exception occurs
	 * @throws InvalidPasswordException if the password is not provided or invalid for a protected document
	 */
	public ITextDocumentReader(DSSDocument dssDocument, byte[] passwordProtection) throws IOException, InvalidPasswordException {
		this(dssDocument, passwordProtection, PAdESUtils.DEFAULT_PDF_MEMORY_USAGE_SETTING);
	}

	/**
	 * The OpenPDF implementation of the Reader
	 * 
	 * @param dssDocument {@link DSSDocument} to read
	 * @param passwordProtection binaries of a password to open a protected document
	 * @throws IOException if an exception occurs
	 * @throws InvalidPasswordException if the password is not provided or invalid for a protected document
	 */
	public ITextDocumentReader(DSSDocument dssDocument, byte[] passwordProtection, PdfMemoryUsageSetting pdfMemoryUsageSetting)
			throws IOException, InvalidPasswordException {
		Objects.requireNonNull(dssDocument, "The document must be defined!");
		Objects.requireNonNull(pdfMemoryUsageSetting, "PdfMemoryUsageSetting must be defined!");
		this.dssDocument = dssDocument;
		try {
			if (PdfMemoryUsageSetting.Mode.MEMORY_FULL != pdfMemoryUsageSetting.getMode() && dssDocument instanceof FileDocument) {
				FileDocument fileDocument = (FileDocument) dssDocument;
				this.pdfReader = getFileDocumentPdfReader(fileDocument, passwordProtection, pdfMemoryUsageSetting);

			} else if (dssDocument instanceof InMemoryDocument) {
				InMemoryDocument inMemoryDocument = (InMemoryDocument) dssDocument;
				this.pdfReader = new PdfReader(inMemoryDocument.getBytes(), passwordProtection);

			} else {
				try (InputStream is = dssDocument.openStream()) {
					this.pdfReader = new PdfReader(is, passwordProtection);
				}
			}

		} catch (BadPasswordException e) {
			throw new InvalidPasswordException(String.format("Encrypted document : %s", e.getMessage()));
		}
	}

	private PdfReader getFileDocumentPdfReader(FileDocument fileDocument, byte[] passwordProtection,
											   PdfMemoryUsageSetting pdfMemoryUsageSetting) throws IOException {
		String filenameSource = fileDocument.getFile().getAbsolutePath();
		switch (pdfMemoryUsageSetting.getMode()) {
			case MEMORY_BUFFERED:
				// This condition uses a MappedByteBuffer to process the file in memory
				return new PdfReader(filenameSource, passwordProtection);
			case FILE:
				// NOTE: RandomAccessFileOrArray is closed on PdfReader.close()
				return new PdfReader(new RandomAccessFileOrArray(filenameSource, false, true), passwordProtection);
			default:
				throw new IllegalArgumentException(String.format("The PdfMemoryUsageSetting mode '%s' is not " +
						"supported in dss-pades-openpdf implementation!", pdfMemoryUsageSetting.getMode()));
		}
	}

	/**
	 * The OpenPDF implementation of the Reader
	 * 
	 * @param binaries a byte array of a PDF to read
	 * @param passwordProtection binaries of a password to open a protected document
	 * @throws IOException if an exception occurs
	 * @throws eu.europa.esig.dss.pades.exception.InvalidPasswordException if the password is not provided
	 *                     or invalid for a protected document
	 */
	public ITextDocumentReader(byte[] binaries, byte[] passwordProtection) throws IOException, InvalidPasswordException {
		Objects.requireNonNull(binaries, "The document binaries must be defined!");
		this.dssDocument = new InMemoryDocument(binaries);
		try {
			this.pdfReader = new PdfReader(binaries, passwordProtection);
		} catch (BadPasswordException e) {
            throw new InvalidPasswordException(String.format("Encrypted document : %s", e.getMessage()));
		}
	}
	
	/**
	 * The constructor to directly instantiate the {@code ITextDocumentReader}
	 * 
	 * @param pdfReader {@link PdfReader}
	 */
	public ITextDocumentReader(final PdfReader pdfReader) {
		this.pdfReader = pdfReader;
	}

	/**
	 * Returns the current instance of {@code PdfReader}
	 *
	 * @return {@link PdfReader}
	 */
	public PdfReader getPdfReader() {
		return pdfReader;
	}

	@Override
	public PdfDssDict getDSSDictionary() {
		PdfDict currentCatalog = getCatalogDictionary();
		return SingleDssDict.extract(currentCatalog);
	}

	@Override
	public Map<PdfSignatureDictionary, List<PdfSignatureField>> extractSigDictionaries() {
		if (signatureDictionaryMap == null) {
			signatureDictionaryMap = new LinkedHashMap<>();
			Map<Integer, PdfSigDictWrapper> pdfObjectDictMap = new LinkedHashMap<>();
			
			AcroFields acroFields = pdfReader.getAcroFields();
			Map<String, Item> allFields = acroFields.getAllFields();
			List<String> names = acroFields.getSignedFieldNames();
			LOG.debug("{} signature field(s) found", names.size());
			
			for (String name : names) {
				PdfDictionary pdfField = allFields.get(name).getMerged(0);
				final ITextPdfDict fieldDict = new ITextPdfDict(pdfField);
				final PdfSignatureField pdfSignatureField = new PdfSignatureField(fieldDict);

				int refNumber = 0;
				PdfIndirectReference indirectObject = pdfField.getAsIndirectObject(PdfName.V);
				if (indirectObject != null) {
					refNumber = indirectObject.getNumber();
				}
				PdfSigDictWrapper signature = pdfObjectDictMap.get(refNumber);
				if (signature == null) {
					try {
						PdfDict dictionary = new ITextPdfDict(pdfField.getAsDict(PdfName.V));
						signature = new PdfSigDictWrapper(dictionary);
					} catch (Exception e) {
						LOG.warn("Unable to create a PdfSignatureDictionary for field with name '{}'", name, e);
						continue;
					}

					List<PdfSignatureField> fieldList = new ArrayList<>();
					fieldList.add(pdfSignatureField);
					signatureDictionaryMap.put(signature, fieldList);
					pdfObjectDictMap.put(refNumber, signature);

				} else {
					List<PdfSignatureField> fieldList = signatureDictionaryMap.get(signature);
					fieldList.add(pdfSignatureField);
					LOG.warn("More than one field refers to the same signature dictionary: {}!", fieldList);

				}
			}
		}
		return signatureDictionaryMap;
	}

	@Override
	public void close() {
		pdfReader.close();
	}

	@Override
	public boolean isSignatureCoversWholeDocument(PdfSignatureDictionary signatureDictionary) {
		AcroFields acroFields = pdfReader.getAcroFields();
		List<PdfSignatureField> fields = signatureDictionaryMap.get(signatureDictionary);
		if (Utils.isCollectionNotEmpty(fields)) {
			return acroFields.signatureCoversWholeDocument(fields.get(0).getFieldName());
		}
		throw new DSSException("Not applicable use of the method isSignatureCoversWholeDocument. " +
				"The requested signatureDictionary does not exist!");
	}

	@Override
	public int getNumberOfPages() {
		return pdfReader.getNumberOfPages();
	}

	@Override
	public AnnotationBox getPageBox(int page) {
		Rectangle pageRectangle = pdfReader.getPageSize(page);
		return new AnnotationBox(pageRectangle.getLeft(), pageRectangle.getBottom(), pageRectangle.getRight(), pageRectangle.getTop());
	}

	@Override
	public int getPageRotation(int page) {
		return pdfReader.getPageRotation(page);
	}

	@Override
	public List<PdfAnnotation> getPdfAnnotations(int page) {
		PdfDictionary pageDictionary = pdfReader.getPageN(page);
		PdfArray annots = pageDictionary.getAsArray(PdfName.ANNOTS);
		if (annots != null) {
			List<PdfAnnotation> pdfAnnotations = new ArrayList<>();

			int pageRotation = getPageRotation(page);
			for (PdfObject pdfObject : annots.getElements()) {
				PdfAnnotation pdfAnnotation = toPdfAnnotation(pdfObject, pageRotation);
				if (pdfAnnotation != null) {
					pdfAnnotations.add(pdfAnnotation);
				}
			}
			return pdfAnnotations;
			
		}
		return Collections.emptyList();
	}
	
	private PdfAnnotation toPdfAnnotation(PdfObject pdfObject, int pageRotation) {
		PdfDictionary annotDictionary = getAnnotDictionary(pdfObject);
		if (annotDictionary != null) {
			AnnotationBox annotationBox = getAnnotationBox(annotDictionary);
			if (annotationBox != null) {
				if (isNoRotate(annotDictionary)) {
					annotationBox = ImageRotationUtils.ensureNoRotate(annotationBox, pageRotation);
				}
				PdfAnnotation pdfAnnotation = new PdfAnnotation(annotationBox);
				pdfAnnotation.setName(getSignatureFieldName(annotDictionary));
				pdfAnnotation.setSigned(isSignedField(annotDictionary));
				return pdfAnnotation;
			}
		}
		return null;
	}

	private boolean isNoRotate(PdfDictionary annotDictionary) {
		PdfNumber pdfNumber = annotDictionary.getAsNumber(PdfName.F);
		if (pdfNumber != null) {
			int ff = pdfNumber.intValue();
			return (ff & com.lowagie.text.pdf.PdfAnnotation.FLAGS_NOROTATE) == com.lowagie.text.pdf.PdfAnnotation.FLAGS_NOROTATE;
		}
		return false;
	}
	
	private PdfDictionary getAnnotDictionary(PdfObject pdfObject) {
		if (pdfObject.isIndirect()) {
			pdfObject = PdfReader.getPdfObject(pdfObject);
		}
		if (pdfObject.isDictionary()) {
			return (PdfDictionary) pdfObject;
		}
		return null;
	}
	
	private AnnotationBox getAnnotationBox(PdfDictionary annotDictionary) {
		PdfArray annotRect = annotDictionary.getAsArray(PdfName.RECT);
		if (annotRect.size() == 4) {
			PdfNumber pdfNumber0 = annotRect.getAsNumber(0);
			PdfNumber pdfNumber1 = annotRect.getAsNumber(1);
			PdfNumber pdfNumber2 = annotRect.getAsNumber(2);
			PdfNumber pdfNumber3 = annotRect.getAsNumber(3);
			if (pdfNumber0 != null && pdfNumber1 != null && pdfNumber2 != null && pdfNumber3 != null) {
				return new AnnotationBox(
						pdfNumber0.intValue(), 
						pdfNumber1.intValue(), 
						pdfNumber2.intValue(), 
						pdfNumber3.intValue());
			} else {
				LOG.debug("Wrong type of an array entry found in RECT dictionary. Skip the annotation.");
			}
			
		} else {
			LOG.debug("Annotation RECT contains wrong amount of elements. 4 entries is expected.");
		}
		return null;
	}
	
	private String getSignatureFieldName(PdfDictionary annotDictionary) {
		PdfString pdfString = annotDictionary.getAsString(PdfName.T);
		if (pdfString != null) {
			return pdfString.toString();
		}
		return null;
	}

	private boolean isSignedField(PdfDictionary annotDictionary) {
		return annotDictionary.getAsDict(PdfName.V) != null;
	}

	/**
	 * Gets {@code PdfObject} from the PDF by the given {@code objectKey}
	 *
	 * @param objectKey {@link PdfObjectKey} to get object for
	 * @return {@link PdfObject} when the object corresponding to the defined key found, NULL otherwise
	 */
	public PdfObject getObjectByKey(PdfObjectKey objectKey) {
		if (objectKey instanceof ITextObjectKey) {
			ITextObjectKey iTextObjectKey = (ITextObjectKey) objectKey;
			return pdfReader.getPdfObject(iTextObjectKey.getValue().getNumber());
		}
		throw new IllegalStateException("objectKey shall be of type 'ITextObjectKey'!");
	}

	/**
	 * Creates a {@code PdfStream} with given {@code binaries}
	 *
	 * @param binaries binary array to be included to the stream
	 * @return {@link PdfStream}
	 */
	public PdfStream createPdfStream(byte[] binaries) {
		return new PdfStream(binaries);
	}

	@Override
	public BufferedImage generateImageScreenshot(int page) {
		throw new UnsupportedOperationException("The image generation is not supported with OpenPDF implementation!");
	}

	@Override
	public BufferedImage generateImageScreenshotWithoutAnnotations(int page, List<PdfAnnotation> annotations) {
		throw new UnsupportedOperationException("The image generation is not supported with OpenPDF implementation!");
	}

	@Override
	public boolean isEncrypted() {
		return pdfReader.isEncrypted();
	}

	@Override
	public boolean isOpenWithOwnerAccess() {
		return !isEncrypted() || pdfReader.isOwnerPasswordUsed();
	}

	@Override
	public boolean canFillSignatureForm() {
		if (!isOpenWithOwnerAccess()) {
			int permissions = pdfReader.getPermissions();
			return isAllowModifyAnnotations(permissions) || isAllowFillIn(permissions);
		}
		return true;
	}

	@Override
	public boolean canCreateSignatureField() {
		if (!isOpenWithOwnerAccess()) {
			int permissions = pdfReader.getPermissions();
			return isAllowModifyContents(permissions) && isAllowModifyAnnotations(permissions);
		}
		return true;
	}

	private boolean isAllowModifyContents(int permissions) {
		return isPermissionBitPresent(permissions, PdfWriter.ALLOW_MODIFY_CONTENTS);
	}

	private boolean isAllowModifyAnnotations(int permissions) {
		return isPermissionBitPresent(permissions, PdfWriter.ALLOW_MODIFY_ANNOTATIONS);
	}

	private boolean isAllowFillIn(int permissions) {
		return isPermissionBitPresent(permissions, PdfWriter.ALLOW_FILL_IN);
	}

	private boolean isPermissionBitPresent(int permissions, int permissionBit) {
		return (permissionBit & permissions) > 0;
	}

	@Override
	public CertificationPermission getCertificationPermission() {
		int certificationLevel = pdfReader.getCertificationLevel();
		if (certificationLevel > 0) {
			return CertificationPermission.fromCode(certificationLevel);
		}
		return null;
	}

	@Override
	public boolean isUsageRightsSignaturePresent() {
		PdfDictionary catalog = pdfReader.getCatalog();
		if (catalog != null) {
			PdfDictionary permsDict = catalog.getAsDict(PdfName.PERMS);
			if (permsDict != null) {
				PdfObject object = permsDict.get(PdfName.UR);
				if (object != null) {
					return true;
				}
				object = permsDict.get(PdfName.UR3);
				if (object != null) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public PdfDict getCatalogDictionary() {
		return new ITextPdfDict(pdfReader.getCatalog());
	}

	/**
	 * Computes a DocumentId in a deterministic way based on the given {@code parameters} and the document
	 *
	 * @param parameters {@link PAdESCommonParameters}
	 * @return {@link PdfObject} representing an /ID entry containing a deterministic identifier
	 */
	public PdfObject generateDocumentId(PAdESCommonParameters parameters) {
		/*
		 * Computation is according to "14.4 File identifiers"
		 */
		String deterministicId = parameters.getDeterministicId();
		if (dssDocument != null) {
			if (dssDocument.getName() != null) {
				deterministicId = deterministicId + "-" + dssDocument.getName();
			}
			deterministicId = deterministicId + "-" + DSSUtils.getFileByteSize(dssDocument);
		}

		final String md5 = DSSUtils.getMD5Digest(deterministicId.getBytes());
		final byte[] bytes = Utils.fromHex(md5);

		// see {@code com.lowagie.text.pdf.PdfEncryption.createInfoId(byte[] idPartOne, byte[] idPartTwo)}
		try (ByteBuffer buf = new ByteBuffer(90)) {
			buf.append('[').append('<');
			for (int k = 0; k < 16; ++k) {
				buf.appendHex(bytes[k]);
			}
			/*
			 * When a PDF file is first written, both identifiers shall be set to the same value.
			 */
			buf.append('>').append('<');
			for (int k = 0; k < 16; ++k) {
				buf.appendHex(bytes[k]);
			}
			buf.append('>').append(']');
			return new PdfLiteral(buf.toByteArray());

		} catch (IOException e) {
			throw new DSSException("Unable to generate the fileId", e);
		}
	}

	@Override
	public float getPdfHeaderVersion() {
		// last char is returned, for instance for "1.x", the returned result is "x"
		char pdfVersionLastChar = pdfReader.getPdfVersion();

		float numVersion = 1 + Character.getNumericValue(pdfVersionLastChar) / 10f; // transform to "1 + 0.x = 1.x"
		if (numVersion == 1) {
			// OpenPdf returns 0 for PDF 2.0
			++numVersion; // TODO : improve
		}
		return numVersion;
	}

	@Override
	public float getVersion() {
		float version = getPdfHeaderVersion();
		PdfDictionary catalog = pdfReader.getCatalog();
		try {
			if (catalog != null) {
				PdfName versionName = catalog.getAsName(PdfName.VERSION);
				if (versionName != null) {
					version = Float.parseFloat(PdfName.decodeName(versionName.toString()));
				}
			}
		} catch (Exception e) {
			LOG.warn("An error occurred on catalog /Version extraction : {}", e.getMessage(), e);
		}
		return version;
	}

	@Override
	public void setVersion(float version) {
		pdfReader.getCatalog().put(PdfName.VERSION, new PdfName(PdfName.encodeName(Float.toString(version))));
	}

	@Override
	public PdfDict createPdfDict() {
		return new ITextPdfDict();
	}

	@Override
	public eu.europa.esig.dss.pdf.PdfArray createPdfArray() {
		return new ITextPdfArray();
	}

}
