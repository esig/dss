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

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSConfigurationException;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.x509.SignatureForm;
import eu.europa.esig.dss.x509.tsp.TSPSource;

/**
 * Base class for extending a CAdESSignature.
 *
 *
 */

abstract class CAdESSignatureExtension implements SignatureExtension<CAdESSignatureParameters> {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignatureExtension.class);

	protected final TSPSource signatureTsa;

	/**
	 * true if only the last signature must be extended
	 */
	private final boolean onlyLastCMSSignature;

	/**
	 * @param signatureTsa
	 * @param onlyLastCMSSignature true if only the last signature must be extended, otherwise all signatures are extended
	 */
	public CAdESSignatureExtension(final TSPSource signatureTsa, final boolean onlyLastCMSSignature) {

		this.signatureTsa = signatureTsa;
		this.onlyLastCMSSignature = onlyLastCMSSignature;
		if (signatureTsa == null) {
			throw new DSSConfigurationException(DSSConfigurationException.MSG.CONFIGURE_TSP_SERVER);
		}
	}

	/**
	 * @return the TSA used for the signature-time-stamp attribute
	 */
	public TSPSource getSignatureTsa() {

		return signatureTsa;
	}

	/**
	 * @param signatureToExtend   to be extended
	 * @param parameters of the extension
	 * @return a new extended document
	 * @throws eu.europa.esig.dss.DSSException
	 */
	@Override
	public CMSSignedDocument extendSignatures(final DSSDocument signatureToExtend, final CAdESSignatureParameters parameters) throws DSSException {

		LOG.info("EXTEND SIGNATURES.");
		try {
			final InputStream inputStream = signatureToExtend.openStream();
			final CMSSignedData cmsSignedData = new CMSSignedData(inputStream);
			IOUtils.closeQuietly(inputStream);
			final CMSSignedData extendCMSSignedData = extendCMSSignatures(cmsSignedData, parameters);
			final CMSSignedDocument cmsSignedDocument = new CMSSignedDocument(extendCMSSignedData);
			return cmsSignedDocument;
		} catch (CMSException e) {
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
		Collection<SignerInformation> signerInformationCollection = cmsSignedData.getSignerInfos().getSigners();
		for (SignerInformation signerInformation : signerInformationCollection) {
			cmsSignedData = preExtendCMSSignedData(cmsSignedData, parameters);
		}

		signerInformationCollection = cmsSignedData.getSignerInfos().getSigners();

		final List<SignerInformation> newSignerInformationList = new ArrayList<SignerInformation>();
		for (SignerInformation signerInformation : signerInformationCollection) {

			final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
			cadesSignature.setDetachedContents(parameters.getDetachedContent());
			assertSignatureValid(cadesSignature, parameters);
			final SignerInformation newSignerInformation = extendCMSSignature(cmsSignedData, signerInformation, parameters);
			newSignerInformationList.add(newSignerInformation);
		}

		final SignerInformationStore newSignerStore = new SignerInformationStore(newSignerInformationList);
		cmsSignedData = CMSSignedData.replaceSigners(cmsSignedData, newSignerStore);
		signerInformationCollection = cmsSignedData.getSignerInfos().getSigners();
		for (SignerInformation signerInformation : signerInformationCollection) {
			cmsSignedData = postExtendCMSSignedData(cmsSignedData, signerInformation, parameters);
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
		final List<SignerInformation> newSignerInformationList = new ArrayList<SignerInformation>();
		for (SignerInformation signerInformation : signerInformationCollection) {

			if (lastSignerInformation == signerInformation) {

				final CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
				cadesSignature.setDetachedContents(parameters.getDetachedContent());
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
		cmsSignedData = postExtendCMSSignedData(cmsSignedData, lastSignerInformation, parameters);
		return cmsSignedData;
	}

	private SignerInformation getFirstSigner(CMSSignedData cmsSignedData) {
		final Collection<SignerInformation> signers = cmsSignedData.getSignerInfos().getSigners();
		SignerInformation lastSignerInformation;
		lastSignerInformation = null;
		for (SignerInformation signerInformation : signers) {
			lastSignerInformation = signerInformation;
			break;
		}
		return lastSignerInformation;
	}

	private void assertSignatureValid(final CAdESSignature cadesSignature, final CAdESSignatureParameters parameters) {

		if (! SignatureForm.PAdES.equals(parameters.getSignatureLevel().getSignatureForm())) {

			final SignatureCryptographicVerification signatureCryptographicVerification = cadesSignature.checkSignatureIntegrity();
			if (!signatureCryptographicVerification.isSignatureIntact()) {

				final String errorMessage = signatureCryptographicVerification.getErrorMessage();
				throw new DSSException("Cryptographic signature verification has failed" + (errorMessage.isEmpty() ? "." : (" / " + errorMessage)));
			}
		}
	}

	/**
	 * Extends the signer
	 *
	 * @param signedData
	 * @param signerInformation
	 * @param parameters
	 * @return
	 * @throws java.io.IOException
	 */
	abstract protected SignerInformation extendCMSSignature(CMSSignedData signedData, SignerInformation signerInformation, CAdESSignatureParameters parameters) throws DSSException;

	/**
	 * Extends the root Signed Data. Nothing to do by default.
	 *
	 * @param cmsSignedData
	 * @param parameters
	 * @return
	 */
	protected CMSSignedData preExtendCMSSignedData(CMSSignedData cmsSignedData, CAdESSignatureParameters parameters) {
		return cmsSignedData;
	}

	/**
	 * Extends the root Signed Data. Nothing to do by default.
	 *
	 * @param cmsSignedData
	 * @param signerInformation
	 * @param parameters
	 * @return
	 */
	protected CMSSignedData postExtendCMSSignedData(CMSSignedData cmsSignedData, SignerInformation signerInformation, CAdESSignatureParameters parameters) {
		return cmsSignedData;
	}

	protected ASN1Object getTimeStampAttributeValue(TSPSource tspSource, byte[] message, CAdESSignatureParameters parameters) {

		final DigestAlgorithm timestampDigestAlgorithm = parameters.getSignatureTimestampParameters().getDigestAlgorithm();
		ASN1Object signatureTimeStampValue = getTimeStampAttributeValue(tspSource, message, timestampDigestAlgorithm);
		return signatureTimeStampValue;
	}

	public static ASN1Object getTimeStampAttributeValue(final TSPSource tspSource, final byte[] messageToTimestamp, final DigestAlgorithm timestampDigestAlgorithm,
			final Attribute... attributesForTimestampToken) {
		try {

			if (LOG.isDebugEnabled()) {
				LOG.debug("Message to timestamp is: " + Hex.encodeHexString(messageToTimestamp));
			}
			byte[] timestampDigest = DSSUtils.digest(timestampDigestAlgorithm, messageToTimestamp);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Digested ({}) message to timestamp is {}", new Object[]{timestampDigestAlgorithm, Hex.encodeHexString(timestampDigest)});
			}

			final TimeStampToken timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, timestampDigest);

			if (timeStampToken == null) {
				throw new NullPointerException();
			}

			if (LOG.isDebugEnabled()) {
				final byte[] messageImprintDigest = timeStampToken.getTimeStampInfo().getMessageImprintDigest();
				LOG.debug("Digested ({}) message in timestamp is {}", new Object[]{timestampDigestAlgorithm, Hex.encodeHexString(messageImprintDigest)});
			}

			CMSSignedData cmsSignedDataTimeStampToken = new CMSSignedData(timeStampToken.getEncoded());

			// TODO (27/08/2014): attributesForTimestampToken cannot be null: to be modified
			if (attributesForTimestampToken != null) {
				// timeStampToken contains one and only one signer
				final SignerInformation signerInformation = cmsSignedDataTimeStampToken.getSignerInfos().getSigners().iterator().next();
				AttributeTable unsignedAttributes = CAdESSignature.getUnsignedAttributes(signerInformation);
				for (final Attribute attributeToAdd : attributesForTimestampToken) {
					final ASN1ObjectIdentifier attrType = attributeToAdd.getAttrType();
					final ASN1Encodable objectAt = attributeToAdd.getAttrValues().getObjectAt(0);
					unsignedAttributes = unsignedAttributes.add(attrType, objectAt);
				}
				final SignerInformation newSignerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
				final List<SignerInformation> signerInformationList = new ArrayList<SignerInformation>();
				signerInformationList.add(newSignerInformation);
				final SignerInformationStore newSignerStore = new SignerInformationStore(signerInformationList);
				cmsSignedDataTimeStampToken = CMSSignedData.replaceSigners(cmsSignedDataTimeStampToken, newSignerStore);
			}
			final byte[] newTimeStampTokenBytes = cmsSignedDataTimeStampToken.getEncoded();
			return DSSASN1Utils.toASN1Primitive(newTimeStampTokenBytes);
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (CMSException e) {
			throw new DSSException(e);
		}

	}
}
