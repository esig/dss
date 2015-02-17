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

package eu.europa.ec.markt.dss.signature.cades;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
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

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSConfigurationException;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullReturnedException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * Base class for extending a CAdESSignature.
 *
 * @version $Revision$ - $Date$
 */

abstract class CAdESSignatureExtension implements SignatureExtension {

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
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	public CMSSignedDocument extendSignatures(final DSSDocument signatureToExtend, final SignatureParameters parameters) throws DSSException {

		LOG.info("EXTEND SIGNATURES.");
		try {
			final InputStream inputStream = signatureToExtend.openStream();
			final CMSSignedData cmsSignedData = new CMSSignedData(inputStream);
			DSSUtils.closeQuietly(inputStream);
			final CMSSignedData extendCMSSignedData = extendCMSSignatures(cmsSignedData, parameters);
			final CMSSignedDocument cmsSignedDocument = new CMSSignedDocument(extendCMSSignedData);
			return cmsSignedDocument;
		} catch (CMSException e) {
			throw new DSSException("Cannot parse CMS data", e);
		}
	}

	public CMSSignedData extendCMSSignatures(CMSSignedData cmsSignedData, SignatureParameters parameters) {
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
	private CMSSignedData extendAllCMSSignatures(CMSSignedData cmsSignedData, SignatureParameters parameters) {
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
	private CMSSignedData extendLastCMSSignature(CMSSignedData cmsSignedData, SignatureParameters parameters) {

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

	private void assertSignatureValid(final CAdESSignature cadesSignature, final SignatureParameters parameters) {

		// TODO: (Bob: 2014 Jan 22) To be changed to enum check and not string!
		if (!parameters.getSignatureLevel().toString().toLowerCase().startsWith("pades")) {

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
	abstract protected SignerInformation extendCMSSignature(CMSSignedData signedData, SignerInformation signerInformation, SignatureParameters parameters) throws DSSException;

	/**
	 * Extends the root Signed Data. Nothing to do by default.
	 *
	 * @param cmsSignedData
	 * @param parameters
	 * @return
	 */
	protected CMSSignedData preExtendCMSSignedData(CMSSignedData cmsSignedData, SignatureParameters parameters) {
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
	protected CMSSignedData postExtendCMSSignedData(CMSSignedData cmsSignedData, SignerInformation signerInformation, SignatureParameters parameters) {
		return cmsSignedData;
	}

	protected ASN1Object getTimeStampAttributeValue(TSPSource tspSource, byte[] message, SignatureParameters parameters) {

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
				throw new DSSNullReturnedException(TimeStampToken.class);
			}

			if (LOG.isDebugEnabled()) {
				final byte[] messageImprintDigest = timeStampToken.getTimeStampInfo().getMessageImprintDigest();
				LOG.debug("Digested ({}) message in timestamp is {}", new Object[]{timestampDigestAlgorithm, Hex.encodeHexString(messageImprintDigest)});
			}

			CMSSignedData cmsSignedDataTimeStampToken = new CMSSignedData(timeStampToken.getEncoded());

			// TODO (27/08/2014): attributesForTimestampToken cannot be null: to be modified
			if (attributesForTimestampToken != null) {
				// timeStampToken contains one and only one signer
				final SignerInformation signerInformation = (SignerInformation) cmsSignedDataTimeStampToken.getSignerInfos().getSigners().iterator().next();
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
