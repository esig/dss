/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.cades;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSUnsupportedOperationException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.scope.SignatureScopeFinder;
import eu.europa.ec.markt.dss.validation102853.scope.SignatureScopeFinderFactory;

/**
 * Validation of CMS document
 *
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class CMSDocumentValidator extends SignedDocumentValidator {

	protected CMSSignedData cmsSignedData;

	/**
	 * This constructor is used with {@code TimeStampToken}.
	 */
	public CMSDocumentValidator() {
		cadesSignatureScopeFinder = SignatureScopeFinderFactory.geInstance(CAdESSignature.class);
	}

	/**
	 * The default constructor for {@code CMSDocumentValidator}.
	 *
	 * @param cmsSignedData pkcs7-signature(s)
	 */
	public CMSDocumentValidator(final CMSSignedData cmsSignedData) {

		this();
		this.cmsSignedData = cmsSignedData;
	}

	/**
	 * The default constructor for {@code CMSDocumentValidator}.
	 *
	 * @param document document to validate (with the signature(s))
	 * @throws DSSException
	 */
	public CMSDocumentValidator(final DSSDocument document) throws DSSException {

		this();
		this.document = document;
		try {

			final InputStream is = document.openStream();
			if (DSSUtils.available(is) > 0) {
				this.cmsSignedData = new CMSSignedData(is);
			}
		} catch (CMSException e) {
			throw new DSSException("Not a valid CAdES file", e);
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
				// TODO (22/08/2014): This is a List now!
				cadesSignature.setDetachedContent(detachedContents.get(0));
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

	@Override
	protected SignatureScopeFinder getSignatureScopeFinder() {
		return cadesSignatureScopeFinder;
	}
}
