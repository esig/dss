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

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;

public class PdfSignatureRevision extends PdfCMSRevision {

	private final CAdESSignature cades;

	/**
	 * @param cms
	 *            the CMS (CAdES) bytes
	 * @param signatureDictionary
	 *            pdf signature dictionary wrapper
	 * @param dssDictionary
	 *            the DSS dictionary
	 * @param signatureFieldNames
	 *            list of signature field names
	 * @param validationCertPool
	 *            Certificate validation pool
	 * @param originalBytes
	 *            the original bytes of the whole signed document
	 * @param coverCompleteRevision
	 *            identifies if the signature covers the whole revision
	 * @throws IOException
	 *            if an exception occurs
	 */
	public PdfSignatureRevision(byte[] cms, PdfSignatureDictionary signatureDictionary, PdfDssDict dssDictionary, List<String> signatureFieldNames,
			CertificatePool validationCertPool, byte[] originalBytes, boolean coverCompleteRevision) throws IOException {
		super(cms, signatureDictionary, dssDictionary, signatureFieldNames, originalBytes, coverCompleteRevision);
		try {
			cades = new CAdESSignature(cms, validationCertPool);
			final DSSDocument detachedContent = new InMemoryDocument(getSignedDocumentBytes());
			cades.setDetachedContents(Arrays.asList(detachedContent));
		} catch (CMSException e) {
			throw new IOException(e);
		}
	}

	@Override
	protected void checkIntegrityOnce() {
		cades.checkSignatureIntegrity();
	}

	@Override
	public boolean isTimestampRevision() {
		return false;
	}

	public CAdESSignature getCades() {
		return cades;
	}
	
	@Override
	public CMSSignedData getCMSSignedData() {
		return cades.getCmsSignedData();
	}

	@Override
	protected boolean isSignerInformationValidated(SignerInformation signerInformation) {
		return signerInformation == cades.getSignerInformation();
	}

}
