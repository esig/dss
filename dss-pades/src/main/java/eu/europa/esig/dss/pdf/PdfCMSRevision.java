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
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.PdfRevision;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.validation.SignerInfo;

public abstract class PdfCMSRevision implements PdfRevision {

	private static final Logger LOG = LoggerFactory.getLogger(PdfCMSRevision.class);
	
	private final PdfSignatureDictionary signatureDictionary;
	private final PdfDssDict dssDictionary;

	private final byte[] cms;

	/**
	 * The original signed pdf document
	 */
	private final byte[] signedContent;

	private final boolean coverAllOriginalBytes;
	
	private final List<String> signatureFieldNames;
	
	/* Cached attributes */
	private boolean verified;
	private String uniqueId;
	private CMSSignedData cmsSignedData;

	private List<PdfRevision> outerSignatures = new ArrayList<PdfRevision>();

	/**
	 *
	 * @param signatureDictionary
	 *                              The signature dictionary
	 * @param dssDictionary
	 *                              the DSS dictionary
	 * @param cms
	 *                              the signature binary
	 * @param signedContent
	 *                              {@link DSSDocument} the signed content
	 * @param coverAllOriginalBytes
	 *                              true if the signature covers all original bytes
	 */
	protected PdfCMSRevision(byte[] cms, PdfSignatureDictionary signatureDictionary, PdfDssDict dssDictionary, List<String> signatureFieldNames,
			byte[] signedContent, boolean coverAllOriginalBytes) {
		this.cms = cms;
		this.signatureDictionary = signatureDictionary;
		this.dssDictionary = dssDictionary;
		this.signatureFieldNames = signatureFieldNames;
		this.signedContent = signedContent;
		this.coverAllOriginalBytes = coverAllOriginalBytes;
	}

	@Override
	public void checkIntegrity() {
		if (!verified) {
			checkIntegrityOnce();
			if (LOG.isDebugEnabled()) {
				LOG.debug("Verify embedded CAdES Signature on signedBytes size {}.", signedContent.length);
			}
			verified = true;
		}
	}

	protected abstract void checkIntegrityOnce();

	/**
	 * @return the byte of the originally signed document
	 */
	@Override
	public byte[] getSignedDocumentBytes() {
		return signedContent;
	}

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
	public void addOuterSignature(PdfRevision signatureInfo) {
		outerSignatures.add(signatureInfo);
	}

	@Override
	public List<PdfRevision> getOuterSignatures() {
		return Collections.unmodifiableList(outerSignatures);
	}
	
	@Override
	public PdfSignatureDictionary getPdfSigDictInfo() {
		return signatureDictionary;
	}
	
	@Override
	public int[] getSignatureByteRange() {
		return signatureDictionary.getSignatureByteRange();
	}

	@Override
	public Date getSigningDate() {
		return signatureDictionary.getSigningDate();
	}
	
	/**
	 * Returns a built CMSSignedData object
	 */
	public CMSSignedData getCMSSignedData() {
		if (cmsSignedData == null) {
			try {
				cmsSignedData = new CMSSignedData(cms);
			} catch (CMSException e) {
				LOG.warn("Cannot create CMSSignedData object from byte array for signature with name [{}]", signatureFieldNames);
			}
		}
		return cmsSignedData;
	}

	@Override
	public boolean doesSignatureCoverAllOriginalBytes() {
		return coverAllOriginalBytes;
	}
	
	@Override
	public List<String> getFieldNames() {
		return signatureFieldNames;
	}
	
	@Override
	public List<SignerInfo> getSignatureInformationStore() {
		List<SignerInfo> signerInfos = new ArrayList<SignerInfo>();
		SignerInformationStore signerInformationStore = getCMSSignedData().getSignerInfos();
		
		Iterator<SignerInformation> it = signerInformationStore.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signerInformation = it.next();
			SignerId sid = signerInformation.getSID();
			SignerInfo signerInfo = new SignerInfo(sid.getIssuer().toString(), sid.getSerialNumber());
			signerInfo.setValidated(isSignerInformationValidated(signerInformation));
			signerInfos.add(signerInfo);
		}
		
		return signerInfos;
	}
	
	protected abstract boolean isSignerInformationValidated(SignerInformation signerInformation);

}
