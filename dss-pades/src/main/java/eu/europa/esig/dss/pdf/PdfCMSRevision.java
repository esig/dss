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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.validation.ByteRange;
import eu.europa.esig.dss.pdf.modifications.PdfModificationDetection;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.PdfSignatureField;
import org.bouncycastle.cms.CMSSignedData;

import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Defines a PDF revision containing a CMS data (signature/timestamp)
 */
public abstract class PdfCMSRevision implements PdfRevision {

	private static final long serialVersionUID = 7392943800496129517L;

	/**
	 *  The PDF Signature Dictionary
	 */
	private final PdfSignatureDictionary signatureDictionary;

	/**
	 * The signed data binaries
	 */
	private final DSSDocument signedContent;

	/**
	 * Defines if the revision covers all document bytes
	 */
	private final boolean coverAllOriginalBytes;

	/**
	 * A list of signed fields by the corresponding signature
	 */
	private final List<PdfSignatureField> signatureFields;

	/**
	 * Detects the modification in the PDF content
	 */
	private PdfModificationDetection modificationDetection;

	/**
	 * Default constructor
	 *
	 * @param signatureDictionary
	 *                              The signature dictionary
	 * @param signatureFields
	 *                              the list of {@link PdfSignatureField}s
	 * @param signedContent
	 *                              {@link DSSDocument} the signed content
	 * @param coverAllOriginalBytes
	 *                              true if the signature covers all original bytes
	 */
	protected PdfCMSRevision(PdfSignatureDictionary signatureDictionary, List<PdfSignatureField> signatureFields,
							 DSSDocument signedContent, boolean coverAllOriginalBytes) {
		Objects.requireNonNull(signatureDictionary, "The signature dictionary cannot be null!");
		Objects.requireNonNull(signatureFields, "The signature fields must be defined!");
		Objects.requireNonNull(signedContent, "The signed content cannot be null!");
		this.signatureDictionary = signatureDictionary;
		this.signatureFields = signatureFields;
		this.signedContent = signedContent;
		this.coverAllOriginalBytes = coverAllOriginalBytes;
	}

	/**
	 * Gets the bytes of the signature revision
	 *
	 * @return byte array
	 */
	public DSSDocument getSignedData() {
		return signedContent;
	}
	
	@Override
	public PdfSignatureDictionary getPdfSigDictInfo() {
		return signatureDictionary;
	}

	/**
	 * Gets the signed byte range
	 *
	 * @return {@link ByteRange}
	 */
	public ByteRange getByteRange() {
		return signatureDictionary.getByteRange();
	}

	/**
	 * Gets the claimed signing time
	 *
	 * @return {@link Date}
	 */
	public Date getSigningDate() {
		return signatureDictionary.getSigningDate();
	}

	/**
	 * Gets of the all PDF's content is signed
	 *
	 * @return TRUE if the whole PDF is signed, FALSE otherwise
	 */
	public boolean areAllOriginalBytesCovered() {
		return coverAllOriginalBytes;
	}
	
	@Override
	public List<PdfSignatureField> getFields() {
		return signatureFields;
	}

	/**
	 * Gets the CMSSignedData
	 *
	 * @return {@link CMSSignedData}
	 */
	public CMSSignedData getCMSSignedData() {
		return signatureDictionary.getCMSSignedData();
	}

	@Override
	public PdfModificationDetection getModificationDetection() {
		return modificationDetection;
	}

	/**
	 * Sets the {@code PdfModificationDetection} result
	 *
	 * @param modificationDetection {@link PdfModificationDetection}
	 */
	public void setModificationDetection(PdfModificationDetection modificationDetection) {
		this.modificationDetection = modificationDetection;
	}

}
