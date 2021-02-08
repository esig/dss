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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
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
 */

abstract class CAdESSignatureExtension implements SignatureExtension<CAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignatureExtension.class);

	/** The TSPSource to request a timestamp (T- and LTA-levels) */
	protected final TSPSource tspSource;

	/**
	 * The default constructor
	 * 
	 * @param tspSource {@link TSPSource}
	 */
	protected CAdESSignatureExtension(final TSPSource tspSource) {
		Objects.requireNonNull(tspSource, "Missing TSPSource");
		this.tspSource = tspSource;
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
		try (InputStream inputStream = signatureToExtend.openStream()) {
			final CMSSignedData cmsSignedData = new CMSSignedData(inputStream);
			final CMSSignedData extendCMSSignedData = extendCMSSignatures(cmsSignedData, parameters);
			return new CMSSignedDocument(extendCMSSignedData);
		} catch (IOException | CMSException e) {
			throw new DSSException(String.format("Cannot parse CMS data. Reason : %s", e.getMessage()), e);
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
		return extendCMSSignatures(cmsSignedData, Collections.singleton(signerInformation), parameters);
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
	private CMSSignedData extendCMSSignatures(CMSSignedData cmsSignedData, Collection<SignerInformation> signerInformationsToExtend, 
			CAdESSignatureParameters parameters) {
		LOG.info("EXTEND CMS SIGNATURES.");
		assertCMSSignaturesValid(cmsSignedData, signerInformationsToExtend, parameters);

		// extract signerInformations before pre-extension
		Collection<SignerInformation> signerInformationCollection = cmsSignedData.getSignerInfos().getSigners();
		if (Utils.isCollectionEmpty(signerInformationCollection)) {
			throw new DSSException("Unable to extend the document! No signatures found.");
		}
		
		cmsSignedData = preExtendCMSSignedData(cmsSignedData, parameters);
		
		final List<SignerInformation> newSignerInformationList = new ArrayList<>();
		for (SignerInformation signerInformation : signerInformationCollection) {
			SignerInformation newSignerInformation = signerInformation;
			if (signerInformationsToExtend.contains(signerInformation)) {
				newSignerInformation = extendSignerInformation(cmsSignedData, signerInformation, parameters);
				cmsSignedData = extendCMSSignedData(cmsSignedData, newSignerInformation, parameters);
			}
			newSignerInformationList.add(newSignerInformation);
		}

		final SignerInformationStore newSignerStore = new SignerInformationStore(newSignerInformationList);
		cmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, newSignerStore);

		return cmsSignedData;
	}

	/**
	 * Pre-extends the root Signed Data. Executed at the beginning for all {@code SignerInformation}s
	 *
	 * @param cmsSignedData {@link CMSSignedData}
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return extended {@link CMSSignedData}
	 */
	protected CMSSignedData preExtendCMSSignedData(CMSSignedData cmsSignedData, CAdESSignatureParameters parameters) {
		return cmsSignedData;
	}

	/**
	 * Extends the {@code SignerInformation}
	 *
	 * @param signedData {@link CMSSignedData}
	 * @param signerInformation {@link SignerInformation}
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return {@link SignerInformation}
	 */
	protected abstract SignerInformation extendSignerInformation(CMSSignedData signedData, SignerInformation signerInformation, CAdESSignatureParameters parameters);

	/**
	 * Extends the root Signed Data. Nothing to do by default.
	 *
	 * @param cmsSignedData {@link CMSSignedData}
	 * @param signerInformation {@link SignerInformation}
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return extended {@link CMSSignedData}
	 */
	protected CMSSignedData extendCMSSignedData(CMSSignedData cmsSignedData, SignerInformation signerInformation, CAdESSignatureParameters parameters) {
		return cmsSignedData;
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
	protected CAdESSignature newCAdESSignature(CMSSignedData cmsSignedData, SignerInformation signerInformation, List<DSSDocument> detachedContents) {
		final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
		cadesSignature.setDetachedContents(detachedContents);
		return cadesSignature;
	}

	/**
	 * Generates and returns a TimeStamp attribute value
	 *
	 * @param messageToTimestamp binaries to be timestamped
	 * @param timestampDigestAlgorithm {@link DigestAlgorithm} to use
	 * @param attributesForTimestampToken {@link Attribute}s to add
	 * @return {@link ASN1Object} representing a TimeStamp token attribute value
	 */
	protected ASN1Object getTimeStampAttributeValue(final byte[] messageToTimestamp, final DigestAlgorithm timestampDigestAlgorithm,
			final Attribute... attributesForTimestampToken) {
		try {

			if (LOG.isDebugEnabled()) {
				LOG.debug("Message to timestamp is: {}", Utils.toHex(messageToTimestamp));
			}
			byte[] timestampDigest = DSSUtils.digest(timestampDigestAlgorithm, messageToTimestamp);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Digested ({}) message to timestamp is {}", timestampDigestAlgorithm, Utils.toHex(timestampDigest));
			}

			final TimestampBinary timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, timestampDigest);
			CMSSignedData cmsSignedDataTimeStampToken = new CMSSignedData(timeStampToken.getBytes());

			// TODO (27/08/2014): attributesForTimestampToken cannot be null: to be modified
			if (attributesForTimestampToken != null) {
				// timeStampToken contains one and only one signer
				final SignerInformation signerInformation = cmsSignedDataTimeStampToken.getSignerInfos().getSigners().iterator().next();
				AttributeTable unsignedAttributes = CMSUtils.getUnsignedAttributes(signerInformation);
				for (final Attribute attributeToAdd : attributesForTimestampToken) {
					final ASN1ObjectIdentifier attrType = attributeToAdd.getAttrType();
					final ASN1Encodable objectAt = attributeToAdd.getAttrValues().getObjectAt(0);
					unsignedAttributes = unsignedAttributes.add(attrType, objectAt);
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
					assertSignatureValid(cadesSignature);
				}
			}
		}
	}

	private void assertSignatureValid(final CAdESSignature cadesSignature) {
		final SignatureCryptographicVerification signatureCryptographicVerification = cadesSignature.getSignatureCryptographicVerification();
		if (!signatureCryptographicVerification.isSignatureIntact()) {
			final String errorMessage = signatureCryptographicVerification.getErrorMessage();
			throw new DSSException("Cryptographic signature verification has failed" + (errorMessage.isEmpty() ? "." : (" / " + errorMessage)));
		}
	}
	
}
