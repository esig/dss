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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.cades.validation.scope.CAdESSignatureScopeFinder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;

/**
 * Validation of CMS document
 *
 */
public class CMSDocumentValidator extends SignedDocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(CMSDocumentValidator.class);

	protected CMSSignedData cmsSignedData;

	CMSDocumentValidator() {
		this(new CAdESSignatureScopeFinder());
	}
	
	CMSDocumentValidator(SignatureScopeFinder<CAdESSignature> signatureScopeFinder) {
		super(signatureScopeFinder);
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
	 */
	public CMSDocumentValidator(final DSSDocument document) {
		this();
		this.document = document;
		this.cmsSignedData = DSSUtils.toCMSSignedData(document);
	}
	
	protected CMSDocumentValidator(final DSSDocument document, SignatureScopeFinder<CAdESSignature> signatureScopeFinder) {
		this(signatureScopeFinder);
		this.document = document;
		this.cmsSignedData = DSSUtils.toCMSSignedData(document);
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		byte firstByte = DSSUtils.readFirstByte(dssDocument);
		if (DSSASN1Utils.isASN1SequenceTag(firstByte)) {
			return !DSSUtils.isTimestampToken(dssDocument);
		}
		return false;
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		List<AdvancedSignature> signatures = new ArrayList<>();
		if (cmsSignedData != null) {
			for (final SignerInformation signerInformation : cmsSignedData.getSignerInfos().getSigners()) {
				final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
				if (document != null) {
					cadesSignature.setSignatureFilename(document.getName());
				}
				cadesSignature.setDetachedContents(detachedContents);
				cadesSignature.setContainerContents(containerContents);
				cadesSignature.setManifestFile(manifestFile);
				cadesSignature.setSigningCertificateSource(signingCertificateSource);
				cadesSignature.prepareOfflineCertificateVerifier(certificateVerifier);
				signatures.add(cadesSignature);
			}
		}
		return signatures;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(final String signatureId) {
		Objects.requireNonNull(signatureId, "Signature Id cannot be null");

		List<DSSDocument> results = new ArrayList<>();

		for (final SignerInformation signerInformation : cmsSignedData.getSignerInfos().getSigners()) {
			final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
			cadesSignature.setSignatureFilename(document.getName());
			cadesSignature.setDetachedContents(detachedContents);
			cadesSignature.setSigningCertificateSource(signingCertificateSource);
			if (Utils.areStringsEqual(cadesSignature.getId(), signatureId) || isCounterSignature(cadesSignature, signatureId)) {
				results.add(cadesSignature.getOriginalDocument());
			}
		}
		return results;
	}
	
	private boolean isCounterSignature(final CAdESSignature masterSignature, final String signatureId) {
		for (final SignerInformation counterSignerInformation : masterSignature.getCounterSignatureStore()) {
			final CAdESSignature countersignature = new CAdESSignature(cmsSignedData, counterSignerInformation);
			countersignature.setMasterSignature(masterSignature);
			if (Utils.areStringsEqual(countersignature.getId(), signatureId) || isCounterSignature(countersignature, signatureId)) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected CAdESDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
		return new CAdESDiagnosticDataBuilder();
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(final AdvancedSignature advancedSignature) {
		final CAdESSignature cadesSignature = (CAdESSignature) advancedSignature;
		try {
			return Arrays.asList(cadesSignature.getOriginalDocument());
		} catch (DSSException e) {
			LOG.error("Cannot retrieve a list of original documents");
			return Collections.emptyList();
		}
	}

}
