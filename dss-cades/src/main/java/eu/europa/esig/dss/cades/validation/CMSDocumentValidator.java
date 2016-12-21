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
package eu.europa.esig.dss.cades.validation;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.encoders.Base64;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

/**
 * Validation of CMS document
 *
 */
public class CMSDocumentValidator extends SignedDocumentValidator {

	protected CMSSignedData cmsSignedData;
	private static final String BASE64_REGEX = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";

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
			Utils.closeQuietly(inputStream);
		}
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		int headerLength = 500;
		byte[] preamble = new byte[headerLength];
		DSSUtils.readToArray(dssDocument, headerLength, preamble);
		final String preambleString = new String(preamble);
		if (preambleString.getBytes()[0] == 0x30) {
			return true;
		}
		return false;
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		List<AdvancedSignature> signatures = new ArrayList<AdvancedSignature>();
		if (cmsSignedData != null) {
			for (final Object signerInformationObject : cmsSignedData.getSignerInfos().getSigners()) {

				final SignerInformation signerInformation = (SignerInformation) signerInformationObject;
				final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation, validationCertPool);
				cadesSignature.setSignatureFilename(document.getName());
				cadesSignature.setDetachedContents(detachedContents);
				cadesSignature.setProvidedSigningCertificateToken(providedSigningCertificateToken);
				signatures.add(cadesSignature);
			}
		}
		return signatures;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(final String signatureId) throws DSSException {
		if (Utils.isStringBlank(signatureId)) {
			throw new NullPointerException("signatureId");
		}
		List<DSSDocument> results = new ArrayList<DSSDocument>();

		for (final Object signerInformationObject : cmsSignedData.getSignerInfos().getSigners()) {

			final SignerInformation signerInformation = (SignerInformation) signerInformationObject;
			final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation, validationCertPool);
			cadesSignature.setSignatureFilename(document.getName());
			cadesSignature.setDetachedContents(detachedContents);
			cadesSignature.setProvidedSigningCertificateToken(providedSigningCertificateToken);
			if (cadesSignature.getId().equals(signatureId)) {
				if (!cadesSignature.getDetachedContents().isEmpty()) {
					throw new DSSException("The signature must be an enveloping signature");
				}
				byte[] content = CMSUtils.getSignedContent(cmsSignedData.getSignedContent());
				content = isBase64Encoded(content) ? Base64.decode(content) : content;
				results.add(new InMemoryDocument(content));
			}
		}
		return results;
	}

	private boolean isBase64Encoded(byte[] array) {
		return isBase64Encoded(new String(array));
	}

	private boolean isBase64Encoded(String text) {
		Pattern pattern = Pattern.compile(BASE64_REGEX);
		Matcher matcher = pattern.matcher(text);
		return matcher.matches();
	}

}
