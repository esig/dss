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

import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.cms.CMSSignedData;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.validation.PdfModificationDetection;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.validation.ByteRange;

public abstract class PdfCMSRevision implements PdfRevision {

	private final PdfSignatureDictionary signatureDictionary;

	/**
	 * The original signed pdf document
	 */
	private final byte[] signedContent;

	private final boolean coverAllOriginalBytes;
	
	private final List<String> signatureFieldNames;
	
	private PdfModificationDetection modificationDetection;

	/**
	 *
	 * @param signatureDictionary
	 *                              The signature dictionary
	 * @param signatureFieldNames
	 *                              the list of signature field names
	 * @param signedContent
	 *                              {@link DSSDocument} the signed content
	 * @param coverAllOriginalBytes
	 *                              true if the signature covers all original bytes
	 */
	protected PdfCMSRevision(PdfSignatureDictionary signatureDictionary, List<String> signatureFieldNames, byte[] signedContent, 
			boolean coverAllOriginalBytes) {
		Objects.requireNonNull(signatureDictionary, "The signature dictionary cannot be null!");
		Objects.requireNonNull(signatureFieldNames, "The signature field names must be defined!");
		Objects.requireNonNull(signedContent, "The signed content cannot be null!");
		this.signatureDictionary = signatureDictionary;
		this.signatureFieldNames = signatureFieldNames;
		this.signedContent = signedContent;
		this.coverAllOriginalBytes = coverAllOriginalBytes;
	}

	/**
	 * @return the byte of the originally signed document
	 */
	public byte[] getRevisionCoveredBytes() {
		return signedContent;
	}
	
	@Override
	public PdfSignatureDictionary getPdfSigDictInfo() {
		return signatureDictionary;
	}
	
	public ByteRange getByteRange() {
		return signatureDictionary.getByteRange();
	}

	public Date getSigningDate() {
		return signatureDictionary.getSigningDate();
	}

	public boolean areAllOriginalBytesCovered() {
		return coverAllOriginalBytes;
	}
	
	@Override
	public List<String> getFieldNames() {
		return signatureFieldNames;
	}
	
	public CMSSignedData getCMSSignedData() {
		return signatureDictionary.getCMSSignedData();
	}

	@Override
	public PdfModificationDetection getModificationDetection() {
		return modificationDetection;
	}

	public void setModificationDetection(PdfModificationDetection modificationDetection) {
		this.modificationDetection = modificationDetection;
	}

}
