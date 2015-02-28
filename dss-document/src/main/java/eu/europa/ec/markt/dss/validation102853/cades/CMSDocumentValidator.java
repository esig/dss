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
package eu.europa.ec.markt.dss.validation102853.cades;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSUnsupportedOperationException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.scope.CAdESSignatureScopeFinder;

/**
 * Validation of CMS document
 *
 */
public class CMSDocumentValidator extends SignedDocumentValidator {

	protected CMSSignedData cmsSignedData;

	/**
	 * This constructor is used with {@code TimeStampToken}.
	 */
	public CMSDocumentValidator() {
		super(new CAdESSignatureScopeFinder());
	}

	/**
	 * The default constructor for {@code CMSDocumentValidator}.
	 *
	 * @param cmsSignedData
	 *            pkcs7-signature(s)
	 */
	public CMSDocumentValidator(final CMSSignedData cmsSignedData) {

		this();
		this.cmsSignedData = cmsSignedData;
	}

	/**
	 * The default constructor for {@code CMSDocumentValidator}.
	 *
	 * @param document
	 *            document to validate (with the signature(s))
	 * @throws DSSException
	 */
	public CMSDocumentValidator(final DSSDocument document) throws DSSException {

		this();
		this.document = document;
		InputStream inputStream = null;
		try {

			inputStream = document.openStream();
			if (DSSUtils.available(inputStream) > 0) {
				this.cmsSignedData = new CMSSignedData(inputStream);
			}
		} catch (CMSException e) {
			throw new DSSException("Not a valid CAdES file", e);
		} finally {
			IOUtils.closeQuietly(inputStream);
		}
	}

	@Override
	public List<AdvancedSignature> getSignatures() {

		if (signatures != null) {
			return signatures;
		}
		signatures = new ArrayList<AdvancedSignature>();
		if (cmsSignedData != null) {

			for (final Object signerInformationObject : cmsSignedData.getSignerInfos().getSigners()) {

				final SignerInformation signerInformation = (SignerInformation) signerInformationObject;
				final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation, validationCertPool);
				cadesSignature.setDetachedContents(detachedContents);
				cadesSignature.setProvidedSigningCertificateToken(providedSigningCertificateToken);
				signatures.add(cadesSignature);
			}
		}
		return signatures;
	}

	@Override
	public DSSDocument removeSignature(final String signatureId) throws DSSException {
		throw new DSSUnsupportedOperationException("This method is not applicable for this kind of signatures!");
	}

}
