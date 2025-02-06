/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzer;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Base class for extending a CAdESSignature.
 *
 */
abstract class CAdESSignatureExtension implements SignatureExtension<CAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignatureExtension.class);

	/** The TSPSource to request a timestamp (T- and LTA-levels) */
	protected final TSPSource tspSource;

	/** The CertificateVerifier to use */
	protected final CertificateVerifier certificateVerifier;

	/**
	 * The default constructor
	 * 
	 * @param tspSource {@link TSPSource}
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	protected CAdESSignatureExtension(final TSPSource tspSource, final CertificateVerifier certificateVerifier) {
		Objects.requireNonNull(tspSource, "Missing TSPSource");
		this.tspSource = tspSource;
		this.certificateVerifier = certificateVerifier;
	}

	/**
	 * @param signatureToExtend
	 *            {@link DSSDocument} to be extended
	 * @param parameters
	 *            {@link CAdESSignatureParameters} of the extension
	 * @return {@link CMSSignedDocument} a new extended document
	 */
	@Override
	public CMSSignedDocument extendSignatures(final DSSDocument signatureToExtend, final CAdESSignatureParameters parameters) {
		LOG.trace("EXTEND SIGNATURES.");
		final CMSSignedData cmsSignedData = getCMSSignedData(signatureToExtend);
		final CMSSignedData extendCMSSignedData = extendCMSSignatures(cmsSignedData, parameters);
		return new CMSSignedDocument(extendCMSSignedData);
	}

	private CMSSignedData getCMSSignedData(DSSDocument document) {
		if (document instanceof CMSSignedDocument) {
			return ((CMSSignedDocument) document).getCMSSignedData();
		} else {
			try (InputStream inputStream = document.openStream()) {
				return new CMSSignedData(inputStream);
			} catch (IOException | CMSException e) {
				throw new IllegalInputException(String.format("Cannot parse CMS data. Reason : %s", e.getMessage()), e);
			}
		}
	}

	/**
	 * Extends a {@code CMSSignedData}
	 * 
	 * @param cmsSignedData {@link CMSSignedData} to extend
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return {@link CMSSignedData}
	 */
	public CMSSignedData extendCMSSignatures(CMSSignedData cmsSignedData, CAdESSignatureParameters parameters) {
		return extendCMSSignatures(cmsSignedData, cmsSignedData.getSignerInfos().getSigners(), parameters);
	}

	/**
	 * Extends a {@code CMSSignedData} with a specified {@code SignerInformation}
	 * NOTE: does not modify other {@code SignerInformation}s
	 * 
	 * @param cmsSignedData {@link CMSSignedData} to extend
	 * @param signerInformation {@link SignerInformation} to extend
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return {@link CMSSignedData}
	 */
	public CMSSignedData extendCMSSignatures(CMSSignedData cmsSignedData, SignerInformation signerInformation, CAdESSignatureParameters parameters) {
		return extendCMSSignatures(cmsSignedData, Collections.singletonList(signerInformation), parameters);
	}

	/**
	 * Loops on each signerInformation of the {@code cmsSignedData} and 
	 * extends ones defined in the collection {@code signerInformationsToExtend}
	 *
	 * @param cmsSignedData {@link CMSSignedData}
	 * @param signerInformationsToExtend a collection of {@link SignerInformation} to be extended
	 * @param parameters {@link CAdESSignatureParameters} for the extension
	 * @return {@link CMSSignedData} with extended signerInformations
	 */
	protected CMSSignedData extendCMSSignatures(CMSSignedData cmsSignedData,
												Collection<SignerInformation> signerInformationsToExtend,
												CAdESSignatureParameters parameters) {
		LOG.info("EXTEND CMS SIGNATURES.");
		assertCMSSignaturesValid(cmsSignedData, signerInformationsToExtend, parameters);

		// extract signerInformations before pre-extension
		Collection<SignerInformation> signerInformationCollection = cmsSignedData.getSignerInfos().getSigners();
		if (Utils.isCollectionEmpty(signerInformationCollection)) {
			throw new IllegalInputException("Unable to extend the document! No signatures found.");
		}

		List<String> signatureIdsToExtend = new ArrayList<>();

		CMSDocumentAnalyzer validator = getDocumentValidator(cmsSignedData, parameters);
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			CAdESSignature cadesSignature = (CAdESSignature) signature;
			if (signerInformationsToExtend.contains(cadesSignature.getSignerInformation())) {
				signatureIdsToExtend.add(cadesSignature.getId());
			}
		}

		return extendCMSSignatures(cmsSignedData, parameters, signatureIdsToExtend);
	}

	/**
	 * This method extends the signatures in the {@code cmsSignedData} with ids listed
	 * within {@code signatureIdsToExtend}
	 *
	 * @param cmsSignedData {@link CMSSignedData} containing the signatures to be extended
	 * @param parameters {@link CAdESSignatureParameters}
	 * @param signatureIdsToExtend a list of {@link String} signature Ids to be extended
	 * @return {@link CMSSignedData}
	 */
	protected abstract CMSSignedData extendCMSSignatures(CMSSignedData cmsSignedData,
												CAdESSignatureParameters parameters,
												List<String> signatureIdsToExtend);

	/**
	 * This method replaces the signers within the provided {@code cmsSignedData}
	 *
	 * @param cmsSignedData {@link CMSSignedData} to replace SignerInformations within
	 * @param newSignerInformationList a list of new {@link SignerInformation}s
	 * @return {@link CMSSignedData}
	 */
	protected CMSSignedData replaceSigners(CMSSignedData cmsSignedData, List<SignerInformation> newSignerInformationList) {
		final SignerInformationStore newSignerStore = new SignerInformationStore(newSignerInformationList);
		CMSSignedData updatedCmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, newSignerStore);
		return CMSUtils.populateDigestAlgorithmSet(updatedCmsSignedData, cmsSignedData);
	}
	
	/**
	 * Creates a CAdESSignature.
	 * Note: recommended method to use.
	 * 
	 * @param cmsSignedData {@link CMSSignedData} of a signature to create
	 * @param signerInformation {@link SignerInformation}
	 * @param detachedContents a list of detached {@link DSSDocument}s
	 * @return created {@link CAdESSignature}
	 */
	protected CAdESSignature newCAdESSignature(CMSSignedData cmsSignedData, SignerInformation signerInformation,
											   List<DSSDocument> detachedContents) {
		final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
		cadesSignature.setDetachedContents(detachedContents);
		cadesSignature.initBaselineRequirementsChecker(certificateVerifier);
		return cadesSignature;
	}

	/**
	 * Generates and returns a TimeStamp attribute value
	 *
	 * @param timestampMessageDigest {@link DSSMessageDigest} message-digest to be timestamped
	 * @param timestampDigestAlgorithm {@link DigestAlgorithm} to use
	 * @param attributesForTimestampToken {@link Attribute}s to add
	 * @return {@link ASN1Object} representing a TimeStamp token attribute value
	 */
	protected ASN1Object getTimeStampAttributeValue(
			final DSSMessageDigest timestampMessageDigest, final DigestAlgorithm timestampDigestAlgorithm,
			final Attribute... attributesForTimestampToken) {
		try {

			if (LOG.isDebugEnabled()) {
				LOG.debug("Message to timestamp is {}", timestampMessageDigest);
			}

			final TimestampBinary timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, timestampMessageDigest.getValue());
			CMSSignedData cmsSignedDataTimeStampToken = new CMSSignedData(timeStampToken.getBytes());

			// TODO (27/08/2014): attributesForTimestampToken cannot be null: to be modified
			if (attributesForTimestampToken != null) {
				// timeStampToken contains one and only one signer
				final SignerInformation signerInformation = cmsSignedDataTimeStampToken.getSignerInfos().getSigners().iterator().next();
				AttributeTable unsignedAttributes = CMSUtils.getUnsignedAttributes(signerInformation);
				for (final Attribute attributeToAdd : attributesForTimestampToken) {
					final ASN1ObjectIdentifier attrType = attributeToAdd.getAttrType();
					if (attributeToAdd.getAttrValues().size() == 0) {
						LOG.warn("No values found within an unsigned attribute. The attribute is skipped.");
						continue;
					} else if (attributeToAdd.getAttrValues().size() != 1) {
						LOG.warn("More than one value found within a signature unsigned attribute. Only the first value will be preserved.");
					}
					final ASN1Encodable attrValue = attributeToAdd.getAttrValues().getObjectAt(0);
					if (attrValue != null) {
						unsignedAttributes = unsignedAttributes.add(attrType, attrValue);
					} else {
						throw new DSSException("Invalid encoding of an unsigned attribute found! Unable to extend. See more details in the logs.");
					}
				}
				// Unsigned attributes cannot be empty (RFC 5652 5.3)
				if (unsignedAttributes.size() == 0) {
					unsignedAttributes = null;
				}
				final SignerInformation newSignerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
				final List<SignerInformation> signerInformationList = new ArrayList<>();
				signerInformationList.add(newSignerInformation);
				final SignerInformationStore newSignerStore = new SignerInformationStore(signerInformationList);
				cmsSignedDataTimeStampToken = CMSSignedData.replaceSigners(cmsSignedDataTimeStampToken, newSignerStore);
			}
			final byte[] newTimeStampTokenBytes = cmsSignedDataTimeStampToken.getEncoded();
			return DSSASN1Utils.toASN1Primitive(newTimeStampTokenBytes);
		} catch (IOException | CMSException e) {
			throw new DSSException("Cannot obtain timestamp attribute value.", e);
		}
	}

	private void assertCMSSignaturesValid(final CMSSignedData cmsSignedData, Collection<SignerInformation> signerInformationsToExtend, 
			CAdESSignatureParameters parameters) {
		if (!SignatureForm.PAdES.equals(parameters.getSignatureLevel().getSignatureForm())) {
			Collection<SignerInformation> signerInformationCollection = cmsSignedData.getSignerInfos().getSigners();
			for (SignerInformation signerInformation : signerInformationCollection) {
				if (signerInformationsToExtend.contains(signerInformation)) {
					CAdESSignature cadesSignature = newCAdESSignature(cmsSignedData, signerInformation, parameters.getDetachedContents());
					assertSignatureValid(cadesSignature, parameters);
				}
			}
		}
	}

	private void assertSignatureValid(final CAdESSignature cadesSignature, final CAdESSignatureParameters parameters) {
		if (parameters.isGenerateTBSWithoutCertificate() && cadesSignature.getCertificateSource().getNumberOfCertificates() == 0) {
			LOG.debug("Extension of a signature without TBS certificate. Signature validity is not checked.");
			return;
		}

		final SignatureCryptographicVerification signatureCryptographicVerification = cadesSignature.getSignatureCryptographicVerification();
		if (!signatureCryptographicVerification.isSignatureIntact()) {
			final String errorMessage = signatureCryptographicVerification.getErrorMessage();
			throw new DSSException("Cryptographic signature verification has failed" + (errorMessage.isEmpty() ? "." : (" / " + errorMessage)));
		}
	}

	/**
	 * This method returns a document validator for a {@code CMSSignedData}
	 *
	 * @param signedData {@link CMSSignedData} to get validation for
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return {@link CMSDocumentAnalyzer}
	 */
	protected CMSDocumentAnalyzer getDocumentValidator(CMSSignedData signedData, CAdESSignatureParameters parameters) {
		CMSDocumentAnalyzer documentValidator = new CMSDocumentAnalyzer(signedData);
		documentValidator.setCertificateVerifier(certificateVerifier);
		documentValidator.setDetachedContents(parameters.getDetachedContents());
		documentValidator.setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE);
		return documentValidator;
	}
	
}
