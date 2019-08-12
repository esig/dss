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
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;

public abstract class PdfCMSInfo implements PdfSignatureOrDocTimestampInfo {

	private static final Logger LOG = LoggerFactory.getLogger(PdfCMSInfo.class);
	
	private final PdfSigDict signatureDictionary;
	private final PdfDssDict dssDictionary;

	private final byte[] cms;

	/**
	 * The original signed pdf document
	 */
	private final byte[] signedBytes;

	private final boolean coverAllOriginalBytes;
	private boolean verified;
	private String uniqueId;

	private List<PdfSignatureOrDocTimestampInfo> outerSignatures = new ArrayList<PdfSignatureOrDocTimestampInfo>();

	/**
	 *
	 * @param signatureDictionary
	 *                              The signature dictionary
	 * @param dssDictionary
	 *                              the DSS dictionary
	 * @param cms
	 *                              the signature binary
	 * @param signedContent
	 *                              the signed content
	 * @param coverAllOriginalBytes
	 *                              true if the signature covers all original bytes
	 */
	protected PdfCMSInfo(PdfSigDict signatureDictionary, PdfDssDict dssDictionary, byte[] cms, byte[] signedContent, boolean coverAllOriginalBytes) {
		this.cms = cms;
		this.signatureDictionary = signatureDictionary;
		this.dssDictionary = dssDictionary;
		this.signedBytes = signedContent;
		this.coverAllOriginalBytes = coverAllOriginalBytes;
	}

	@Override
	public void checkIntegrity() {
		if (!verified) {
			checkIntegrityOnce();
			LOG.debug("Verify embedded CAdES Signature on signedBytes size {}.", signedBytes.length);
			verified = true;
		}
	}

	protected abstract void checkIntegrityOnce();

	/**
	 * @return the byte of the originally signed document
	 */
	@Override
	public byte[] getSignedDocumentBytes() {
		return signedBytes;
	}

	@Override
	public PdfDssDict getDssDictionary() {
		return dssDictionary;
	}

	@Override
	public String uniqueId() {
		if (uniqueId == null) {
			byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, cms);
			uniqueId = Utils.toHex(digest);
		}
		return uniqueId;
	}
	
	@Override
	public byte[] getContents() {
		return cms;
	}

	@Override
	public void addOuterSignature(PdfSignatureOrDocTimestampInfo signatureInfo) {
		outerSignatures.add(signatureInfo);
	}

	@Override
	public List<PdfSignatureOrDocTimestampInfo> getOuterSignatures() {
		return Collections.unmodifiableList(outerSignatures);
	}
	
	@Override
	public String getSigFieldName() {
		return signatureDictionary.getSigFieldName();
	}

	@Override
	public String getSignerName() {
		return signatureDictionary.getSignerName();
	}

	@Override
	public String getContactInfo() {
		return signatureDictionary.getContactInfo();
	}

	@Override
	public String getReason() {
		return signatureDictionary.getReason();
	}

	@Override
	public String getLocation() {
		return signatureDictionary.getLocation();
	}

	@Override
	public Date getSigningDate() {
		return signatureDictionary.getSigningDate();
	}

	@Override
	public String getFilter() {
		return signatureDictionary.getFilter();
	}

	@Override
	public String getSubFilter() {
		return signatureDictionary.getSubFilter();
	}

	@Override
	public int[] getSignatureByteRange() {
		return signatureDictionary.getByteRange();
	}
	
	public CMSSignedData getCMSSignedData() {
		CMSSignedData cmsSignedData = null;
		try {
			cmsSignedData = new CMSSignedData(cms);
		} catch (CMSException e) {
			LOG.warn("Cannot create CMSSignedData object from byte array for signature with name [{}]", getSigFieldName());
		}
		return cmsSignedData;
	}

	@Override
	public boolean isCoverAllOriginalBytes() {
		return coverAllOriginalBytes;
	}

}
