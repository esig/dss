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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

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

/**
 * Base class for extending a CAdESSignature.
 */

abstract class CAdESSignatureExtension implements SignatureExtension<CAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignatureExtension.class);

	protected final TSPSource tspSource;

	/**
	 * true if only the last signature must be extended
	 */
	private final boolean onlyLastCMSSignature;

	/**
	 * @param tspSource
	 * @param onlyLastCMSSignature
	 *            true if only the last signature must be extended, otherwise all signatures are extended
	 */
	public CAdESSignatureExtension(final TSPSource tspSource, final boolean onlyLastCMSSignature) {
		Objects.requireNonNull(tspSource, "Missing TSPSource");
		this.tspSource = tspSource;
		this.onlyLastCMSSignature = onlyLastCMSSignature;
	}

	/**
	 * @param signatureToExtend
	 *            to be extended
	 * @param parameters
	 *            of the extension
	 * @return a new extended document
	 */
	@Override
	public CMSSignedDocument extendSignatures(final DSSDocument signatureToExtend, final CAdESSignatureParameters parameters) {
		LOG.info("EXTEND SIGNATURES.");
		try (InputStream inputStream = signatureToExtend.openStream()) {
			final CMSSignedData cmsSignedData = new CMSSignedData(inputStream);
			final CMSSignedData extendCMSSignedData = extendCMSSignatures(cmsSignedData, parameters);
			return new CMSSignedDocument(extendCMSSignedData);
		} catch (IOException | CMSException e) {
			throw new DSSException("Cannot parse CMS data", e);
		}
	}

	public CMSSignedData extendCMSSignatures(CMSSignedData cmsSignedData, CAdESSignatureParameters parameters) {
		CMSSignedData extendCMSSignedData;
		if (onlyLastCMSSignature) {
			extendCMSSignedData = extendLastCMSSignature(cmsSignedData, parameters);
		} else {
			extendCMSSignedData = extendAllCMSSignatures(cmsSignedData, parameters);
		}
		return extendCMSSignedData;
	}

	/**
	 * Loops on each signerInformation of the cmsSignedData and extends the signature
	 *
	 * @param cmsSignedData
	 * @return
	 */
	private CMSSignedData extendAllCMSSignatures(CMSSignedData cmsSignedData, CAdESSignatureParameters parameters) {
		LOG.info("EXTEND ALL CMS SIGNATURES.");

		cmsSignedData = preExtendCMSSignedData(cmsSignedData, parameters);

		Collection<SignerInformation> signerInformationCollection = cmsSignedData.getSignerInfos().getSigners();
		final List<SignerInformation> newSignerInformationList = new ArrayList<>();
		
		for (SignerInformation signerInformation : signerInformationCollection) {
			final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
			cadesSignature.setDetachedContents(parameters.getDetachedContents());
			assertSignatureValid(cadesSignature, parameters);
			final SignerInformation newSignerInformation = extendCMSSignature(cmsSignedData, signerInformation, parameters);
			newSignerInformationList.add(newSignerInformation);
		}
		final SignerInformationStore newSignerStore = new SignerInformationStore(newSignerInformationList);
		
		cmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, newSignerStore);
		signerInformationCollection = cmsSignedData.getSignerInfos().getSigners();
		
		for (SignerInformation signerInformation : signerInformationCollection) {
			cmsSignedData = postExtendCMSSignedData(cmsSignedData, signerInformation, parameters.getDetachedContents());
		}
		
		return cmsSignedData;
	}

	/**
	 * Take the last signerInformation of the cmsSignedData and extends the signature
	 *
	 * @param cmsSignedData
	 * @return
	 */
	private CMSSignedData extendLastCMSSignature(CMSSignedData cmsSignedData, CAdESSignatureParameters parameters) {

		LOG.info("EXTEND LAST CMS SIGNATURES.");
		cmsSignedData = preExtendCMSSignedData(cmsSignedData, parameters);

		Collection<SignerInformation> signerInformationCollection = cmsSignedData.getSignerInfos().getSigners();
		SignerInformation lastSignerInformation = getFirstSigner(cmsSignedData);
		final List<SignerInformation> newSignerInformationList = new ArrayList<>();
		for (SignerInformation signerInformation : signerInformationCollection) {

			if (lastSignerInformation == signerInformation) {

				final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
				cadesSignature.setDetachedContents(parameters.getDetachedContents());
				assertSignatureValid(cadesSignature, parameters);
				final SignerInformation newSignerInformation = extendCMSSignature(cmsSignedData, signerInformation, parameters);
				newSignerInformationList.add(newSignerInformation);
			} else {
				newSignerInformationList.add(signerInformation);
			}
		}

		final SignerInformationStore newSignerStore = new SignerInformationStore(newSignerInformationList);
		cmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, newSignerStore);

		lastSignerInformation = getFirstSigner(cmsSignedData);
		return postExtendCMSSignedData(cmsSignedData, lastSignerInformation, parameters.getDetachedContents());
	}

	protected SignerInformation getFirstSigner(CMSSignedData cmsSignedData) {
		final Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();
		return signers.iterator().next();
	}

	private void assertSignatureValid(final CAdESSignature cadesSignature, final CAdESSignatureParameters parameters) {
		if (!SignatureForm.PAdES.equals(parameters.getSignatureLevel().getSignatureForm())) {
			final SignatureCryptographicVerification signatureCryptographicVerification = cadesSignature.getSignatureCryptographicVerification();
			if (!signatureCryptographicVerification.isSignatureIntact()) {
				final String errorMessage = signatureCryptographicVerification.getErrorMessage();
				throw new DSSException("Cryptographic signature verification has failed" + (errorMessage.isEmpty() ? "." : (" / " + errorMessage)));
			}
		}
	}

	/**
	 * Extends the {@code SignerInformation}
	 *
	 * @param signedData {@link CMSSignedData}
	 * @param signerInformation {@link SignerInformation}
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return {@link SignerInformation}
	 */
	protected abstract SignerInformation extendCMSSignature(CMSSignedData signedData, SignerInformation signerInformation, CAdESSignatureParameters parameters);

	/**
	 * Extends the root Signed Data. Nothing to do by default.
	 *
	 * @param cmsSignedData {@link CMSSignedData}
	 * @param parameters {@link CAdESSignatureParameters}
	 * @return extended {@link CMSSignedData}
	 */
	protected CMSSignedData preExtendCMSSignedData(CMSSignedData cmsSignedData, CAdESSignatureParameters parameters) {
		return cmsSignedData;
	}

	/**
	 * Extends the root Signed Data. Nothing to do by default.
	 *
	 * @param cmsSignedData {@link CMSSignedData}
	 * @param signerInformation {@link SignerInformation}
	 * @param detachedContents list of {@link DSSDocument}s
	 * @return extended {@link CMSSignedData}
	 */
	public CMSSignedData postExtendCMSSignedData(CMSSignedData cmsSignedData, SignerInformation signerInformation, List<DSSDocument> detachedContents) {
		return cmsSignedData;
	}

	protected ASN1Object getTimeStampAttributeValue(byte[] message, CAdESSignatureParameters parameters) {
		final DigestAlgorithm timestampDigestAlgorithm = parameters.getSignatureTimestampParameters().getDigestAlgorithm();
		return getTimeStampAttributeValue(message, timestampDigestAlgorithm);
	}

	public ASN1Object getTimeStampAttributeValue(final byte[] messageToTimestamp, final DigestAlgorithm timestampDigestAlgorithm,
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
}
