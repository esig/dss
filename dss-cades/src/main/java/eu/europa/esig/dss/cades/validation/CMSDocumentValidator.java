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

import eu.europa.esig.dss.cades.validation.scope.CAdESSignatureScopeFinder;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidatorFactory;
import eu.europa.esig.dss.validation.scope.SignatureScopeFinder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Validation of CMS document
 *
 */
public class CMSDocumentValidator extends SignedDocumentValidator {

	private static final Logger LOG = LoggerFactory.getLogger(CMSDocumentValidator.class);

	/** The CMSSignedData to be validated */
	protected CMSSignedData cmsSignedData;

	/**
	 * The empty constructor, instantiate {@link CAdESSignatureScopeFinder}
	 */
	CMSDocumentValidator() {
		// empty
	}

	/**
	 * The default constructor for {@code CMSDocumentValidator}.
	 *
	 * @param cmsSignedData
	 *            pkcs7-signature(s)
	 */
	public CMSDocumentValidator(final CMSSignedData cmsSignedData) {
		this.cmsSignedData = cmsSignedData;
	}

	/**
	 * The default constructor for {@code CMSDocumentValidator}.
	 *
	 * @param document
	 *            document to validate (with the signature(s))
	 */
	public CMSDocumentValidator(final DSSDocument document) {
		Objects.requireNonNull(document, "Document to be validated cannot be null!");
		this.document = document;
		this.cmsSignedData = toCMSSignedData(document);
	}

	private CMSSignedData toCMSSignedData(DSSDocument document) {
		try {
			return DSSUtils.toCMSSignedData(document);
		} catch (Exception e) {
			throw new IllegalInputException(String.format("A CMS file is expected : %s", e.getMessage()), e);
		}
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		byte firstByte = DSSUtils.readFirstByte(dssDocument);
		if (DSSASN1Utils.isASN1SequenceTag(firstByte)) {
			return !DSSUtils.isTimestampToken(dssDocument) && !EvidenceRecordValidatorFactory.isSupportedDocument(dssDocument);
		}
		return false;
	}

	@Override
	protected List<AdvancedSignature> buildSignatures() {
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

	/**
	 * This method returns a CMSSignedData
	 *
	 * @return {@link CMSSignedData}
	 */
	public CMSSignedData getCmsSignedData() {
		return cmsSignedData;
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
