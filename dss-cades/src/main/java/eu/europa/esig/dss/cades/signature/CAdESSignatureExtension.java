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
import eu.europa.esig.dss.cades.CAdESUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzer;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	/** This object is used to create data container objects such as an OutputStream or a DSSDocument */
	protected DSSResourcesHandlerBuilder resourcesHandlerBuilder;

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
	 * This method sets a {@code DSSResourcesHandlerBuilder} to be used for operating with internal objects
	 * during the signature creation procedure.
	 *
	 * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
	 */
	public void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder) {
		this.resourcesHandlerBuilder = resourcesHandlerBuilder;
	}

	/**
	 * Extends CMS signatures provided within the {@code signatureToExtend} document
	 *
	 * @param signatureToExtend
	 *            {@link DSSDocument} to be extended
	 * @param parameters
	 *            {@link CAdESSignatureParameters} of the extension
	 * @return {@link DSSDocument} a new extended document
	 */
	@Override
	public DSSDocument extendSignatures(final DSSDocument signatureToExtend, final CAdESSignatureParameters parameters) {
		LOG.trace("EXTEND SIGNATURES.");
		final CMS cms = getCMS(signatureToExtend);
		final CMS extendedCMS = extendCMSSignatures(cms, parameters);
		return CMSUtils.writeToDSSDocument(extendedCMS, resourcesHandlerBuilder);
	}

	private CMS getCMS(DSSDocument document) {
		return CMSUtils.parseToCMS(document);
	}

	/**
	 * Extends a {@code CMS}
	 * 
	 * @param cms {@link CMS} to extend
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return {@link CMS}
	 */
	public CMS extendCMSSignatures(CMS cms, CAdESSignatureParameters parameters) {
		return extendCMSSignatures(cms, cms.getSignerInfos().getSigners(), parameters);
	}

	/**
	 * Extends a {@code CMS} with a specified {@code SignerInformation}
	 * NOTE: does not modify other {@code SignerInformation}s
	 * 
	 * @param cms {@link CMS} to extend
	 * @param signerInformation {@link SignerInformation} to extend
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return {@link CMS}
	 */
	public CMS extendCMSSignatures(CMS cms, SignerInformation signerInformation, CAdESSignatureParameters parameters) {
		return extendCMSSignatures(cms, Collections.singletonList(signerInformation), parameters);
	}

	/**
	 * Loops on each signerInformation of the {@code cmsSignedData} and 
	 * extends ones defined in the collection {@code signerInformationsToExtend}
	 *
	 * @param cms {@link CMS}
	 * @param signerInformationsToExtend a collection of {@link SignerInformation} to be extended
	 * @param parameters {@link CAdESSignatureParameters} for the extension
	 * @return {@link CMS} with extended signerInformations
	 */
	protected CMS extendCMSSignatures(CMS cms, Collection<SignerInformation> signerInformationsToExtend,
									  CAdESSignatureParameters parameters) {
		LOG.info("EXTEND CMS SIGNATURES.");
		assertCMSSignaturesValid(cms, signerInformationsToExtend, parameters);

		// extract signerInformations before pre-extension
		Collection<SignerInformation> signerInformationCollection = cms.getSignerInfos().getSigners();
		if (Utils.isCollectionEmpty(signerInformationCollection)) {
			throw new IllegalInputException("Unable to extend the document! No signatures found.");
		}

		List<String> signatureIdsToExtend = new ArrayList<>();

		CMSDocumentAnalyzer validator = getDocumentValidator(cms, parameters);
		List<AdvancedSignature> signatures = validator.getSignatures();
		for (AdvancedSignature signature : signatures) {
			CAdESSignature cadesSignature = (CAdESSignature) signature;
			if (signerInformationsToExtend.contains(cadesSignature.getSignerInformation())) {
				signatureIdsToExtend.add(cadesSignature.getId());
			}
		}

		return extendCMSSignatures(cms, parameters, signatureIdsToExtend);
	}

	/**
	 * This method extends the signatures in the {@code cmsSignedData} with ids listed
	 * within {@code signatureIdsToExtend}
	 *
	 * @param cms {@link CMS} containing the signatures to be extended
	 * @param parameters {@link CAdESSignatureParameters}
	 * @param signatureIdsToExtend a list of {@link String} signature Ids to be extended
	 * @return {@link CMS}
	 */
	protected abstract CMS extendCMSSignatures(CMS cms, CAdESSignatureParameters parameters,
											   List<String> signatureIdsToExtend);

	/**
	 * This method replaces the signers within the provided {@code originalCMS}
	 *
	 * @param originalCMS {@link CMS} to replace SignerInformations within
	 * @param newSignerInformationList a list of new {@link SignerInformation}s
	 * @return {@link CMS}
	 */
	protected CMS replaceSigners(CMS originalCMS, List<SignerInformation> newSignerInformationList) {
		final SignerInformationStore newSignerStore = new SignerInformationStore(newSignerInformationList);
		CMS updatedCmsSignedData = CMSUtils.replaceSigners(originalCMS, newSignerStore);
		return CMSUtils.populateDigestAlgorithmSet(updatedCmsSignedData, originalCMS.getDigestAlgorithmIDs());
	}
	
	/**
	 * Creates a CAdESSignature.
	 * Note: recommended method to use.
	 * 
	 * @param cms {@link CMS} of a signature to create
	 * @param signerInformation {@link SignerInformation}
	 * @param detachedContents a list of detached {@link DSSDocument}s
	 * @return created {@link CAdESSignature}
	 */
	protected CAdESSignature newCAdESSignature(CMS cms, SignerInformation signerInformation,
											   List<DSSDocument> detachedContents) {
		final CAdESSignature cadesSignature = new CAdESSignature(cms, signerInformation);
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
		if (LOG.isDebugEnabled()) {
			LOG.debug("Message to timestamp is {}", timestampMessageDigest);
		}

		final TimestampBinary timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, timestampMessageDigest.getValue());
		CMS cms = CMSUtils.parseToCMS(timeStampToken.getBytes());

		// TODO (27/08/2014): attributesForTimestampToken cannot be null: to be modified
		if (attributesForTimestampToken != null) {
			// timeStampToken contains one and only one signer
			final SignerInformation signerInformation = cms.getSignerInfos().getSigners().iterator().next();
			AttributeTable unsignedAttributes = CAdESUtils.getUnsignedAttributes(signerInformation);
			for (final Attribute attributeToAdd : attributesForTimestampToken) {
				final ASN1ObjectIdentifier attrType = attributeToAdd.getAttrType();
				final ASN1Encodable objectAt = attributeToAdd.getAttrValues().getObjectAt(0);
				unsignedAttributes = unsignedAttributes.add(attrType, objectAt);
			}
			// Unsigned attributes cannot be empty (RFC 5652 5.3)
			if (unsignedAttributes.size() == 0) {
				unsignedAttributes = null;
			}
			final SignerInformation newSignerInformation = CMSUtils.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
			final List<SignerInformation> signerInformationList = new ArrayList<>();
			signerInformationList.add(newSignerInformation);
			final SignerInformationStore newSignerStore = new SignerInformationStore(signerInformationList);
			cms = CMSUtils.replaceSigners(cms, newSignerStore);
		}
		final byte[] newTimeStampTokenBytes = cms.getDEREncoded();
		return DSSASN1Utils.toASN1Primitive(newTimeStampTokenBytes);
	}

	private void assertCMSSignaturesValid(final CMS cms, Collection<SignerInformation> signerInformationsToExtend,
										  CAdESSignatureParameters parameters) {
		if (!SignatureForm.PAdES.equals(parameters.getSignatureLevel().getSignatureForm())) {
			Collection<SignerInformation> signerInformationCollection = cms.getSignerInfos().getSigners();
			for (SignerInformation signerInformation : signerInformationCollection) {
				if (signerInformationsToExtend.contains(signerInformation)) {
					CAdESSignature cadesSignature = newCAdESSignature(cms, signerInformation, parameters.getDetachedContents());
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
	 * This method returns a document validator for a {@code CMS}
	 *
	 * @param cms {@link CMS} to get validation for
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return {@link CMSDocumentAnalyzer}
	 */
	protected CMSDocumentAnalyzer getDocumentValidator(CMS cms, CAdESSignatureParameters parameters) {
		CMSDocumentAnalyzer documentValidator = new CMSDocumentAnalyzer(cms);
		documentValidator.setCertificateVerifier(certificateVerifier);
		documentValidator.setDetachedContents(parameters.getDetachedContents());
		documentValidator.setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE);
		return documentValidator;
	}
	
}
