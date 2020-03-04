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

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.ByteRange;
import eu.europa.esig.dss.validation.PdfRevision;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.validation.SignerInfo;

public abstract class PdfCMSRevision implements PdfRevision {

	private final PdfSignatureDictionary signatureDictionary;

	/**
	 * The original signed pdf document
	 */
	private final byte[] signedContent;

	private final boolean coverAllOriginalBytes;
	
	private final List<String> signatureFieldNames;

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
	
    
	@Override
	public List<SignerInfo> getSignatureInformationStore() {
		List<SignerInfo> signerInfos = new ArrayList<>();
		CMSSignedData cmsSignedData = signatureDictionary.getCMSSignedData();
		SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();

		boolean firstValidated = true;
		Iterator<SignerInformation> it = signerInformationStore.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signerInformation = it.next();
			SignerId sid = signerInformation.getSID();
			SignerInfo signerInfo = new SignerInfo(sid.getIssuer().toString(), sid.getSerialNumber());
			signerInfo.setValidated(firstValidated); // TODO : do better after moving the method to a CAdESSignature class
			signerInfos.add(signerInfo);

			firstValidated = false;
		}
		return signerInfos;
	}

}
