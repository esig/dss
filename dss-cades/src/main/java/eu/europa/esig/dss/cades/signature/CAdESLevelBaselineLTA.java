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
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.OID;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.util.TimeStampTokenProductionComparator;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.tsp.TSPSource;

/**
 * This class holds the CAdES-A signature profiles; it supports the later, over time _extension_ of a signature with
 * id-aa-ets-archiveTimestampV2 attributes as defined in ETSI TS 101 733 V1.8.1, clause 6.4.1.
 *
 * "If the certificate-values and revocation-values attributes are not present in the CAdES-BES or CAdES-EPES, then they
 * shall be added to the electronic signature prior to computing the archive time-stamp token." is the reason we extend
 * from the XL profile.
 *
 */
public class CAdESLevelBaselineLTA extends CAdESSignatureExtension {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESLevelBaselineLTA.class);

	private final CAdESLevelBaselineLT cadesProfileLT;
	
	private static final List<ASN1ObjectIdentifier> archiveTimestampOIDs;
	
	static {
		archiveTimestampOIDs = new ArrayList<ASN1ObjectIdentifier>();
		archiveTimestampOIDs.add(OID.id_aa_ets_archiveTimestampV2);
		archiveTimestampOIDs.add(OID.id_aa_ets_archiveTimestampV3);
	}

	public CAdESLevelBaselineLTA(TSPSource tspSource, CertificateVerifier certificateVerifier, boolean onlyLastSigner) {
		super(tspSource, onlyLastSigner);
		cadesProfileLT = new CAdESLevelBaselineLT(tspSource, certificateVerifier, onlyLastSigner);
	}

	@Override
	protected CMSSignedData preExtendCMSSignedData(CMSSignedData cmsSignedData, CAdESSignatureParameters parameters) {
		return cadesProfileLT.extendCMSSignatures(cmsSignedData, parameters);
	}

	@Override
	protected SignerInformation extendCMSSignature(final CMSSignedData cmsSignedData, SignerInformation signerInformation,
			final CAdESSignatureParameters parameters) throws DSSException {

		AttributeTable unsignedAttributes = CMSUtils.getUnsignedAttributes(signerInformation);
		try {
			// add missing validation data to the previous ArchiveTimestamp
			unsignedAttributes = addValidationData(unsignedAttributes, parameters);
			signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
		} catch (IOException | CMSException | TSPException e) {
			LOG.warn("Validation data to a timestamp was not added due the error : {}", e.getMessage());
		}

		CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
		cadesSignature.setDetachedContents(parameters.getDetachedContents());
		
		unsignedAttributes = addArchiveTimestampV3Attribute(cadesSignature, signerInformation, parameters, unsignedAttributes);
		return SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
	}
	
	private AttributeTable addValidationData(AttributeTable unsignedAttributes, final CAdESSignatureParameters parameters) throws IOException, CMSException, TSPException {
		TimeStampToken timestampTokenToExtend = getTimestampTokenToExtend(unsignedAttributes);
		if (timestampTokenToExtend != null) {
			CMSSignedData timestampCMSSignedData = timestampTokenToExtend.toCMSSignedData();
			CMSSignedData extendedTimestampCMSSignedData = cadesProfileLT.postExtendCMSSignedData(
					timestampCMSSignedData, timestampCMSSignedData.getSignerInfos().iterator().next(), parameters);
					
			unsignedAttributes = CMSUtils.replaceAttribute(unsignedAttributes, timestampCMSSignedData, extendedTimestampCMSSignedData);
		}
		return unsignedAttributes;
	}
	
	private TimeStampToken getTimestampTokenToExtend(AttributeTable unsignedAttributes) {
		TimeStampToken lastTimeStampToken = null;
		for (ASN1ObjectIdentifier identifier : archiveTimestampOIDs) {
			lastTimeStampToken = getLastTimeStampTokenWithOid(lastTimeStampToken, unsignedAttributes, identifier);
		}
		return lastTimeStampToken;
	}
	
	private TimeStampToken getLastTimeStampTokenWithOid(TimeStampToken lastTimeStampToken, AttributeTable unsignedAttributes, ASN1ObjectIdentifier asn1ObjectIdentifier) {
		TimeStampTokenProductionComparator comparator = new TimeStampTokenProductionComparator();
		for (TimeStampToken timeStampToken : DSSASN1Utils.findTimeStampTokens(unsignedAttributes, asn1ObjectIdentifier)) {
			if (lastTimeStampToken == null || comparator.after(timeStampToken, lastTimeStampToken)) {
				lastTimeStampToken = timeStampToken; 
			}
		}
		return lastTimeStampToken;
	}

	/**
	 * The input for the archive-time-stamp-v3’s message imprint computation shall be the concatenation (in the
	 * order shown by the list below) of the signed data hash (see bullet 2 below) and certain fields in their binary
	 * encoded
	 * form without any modification and including the tag, length and value octets:
	 * <ol>
	 * <li>The SignedData.encapContentInfo.eContentType.
	 * <li>The octets representing the hash of the signed data. The hash is computed on the same content that was used
	 * for computing the hash value that is encapsulated within the message-digest signed attribute of the
	 * CAdES signature being archive-time-stamped. The hash algorithm applied shall be the same as the hash
	 * algorithm used for computing the archive time-stamp’s message imprint. The inclusion of the hash algorithm
	 * in the SignedData.digestAlgorithms set is recommended.
	 * <li>Fields version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, and
	 * signature within the SignedData.signerInfos’s item corresponding to the signature being archive
	 * time-stamped, in their order of appearance.
	 * <li>A single instance of ATSHashIndex type (created as specified in clause 6.4.2).
	 * </ol>
	 *
	 * @param cadesSignature
	 * @param signerInformation
	 * @param parameters
	 * @param unsignedAttributes
	 */
	private AttributeTable addArchiveTimestampV3Attribute(CAdESSignature cadesSignature, SignerInformation signerInformation,
			CAdESSignatureParameters parameters, AttributeTable unsignedAttributes) {

		final CadesLevelBaselineLTATimestampExtractor timestampExtractor = new CadesLevelBaselineLTATimestampExtractor(cadesSignature);
		final DigestAlgorithm timestampDigestAlgorithm = parameters.getSignatureTimestampParameters().getDigestAlgorithm();
		byte[] originalDocumentDigest = DSSUtils.digest(timestampDigestAlgorithm, cadesSignature.getOriginalDocument());

		final Attribute atsHashIndexAttribute = timestampExtractor.getAtsHashIndex(signerInformation, timestampDigestAlgorithm);

		final byte[] encodedToTimestamp = timestampExtractor.getArchiveTimestampDataV3(signerInformation, atsHashIndexAttribute, originalDocumentDigest);

		final ASN1Object timeStampAttributeValue = getTimeStampAttributeValue(encodedToTimestamp, timestampDigestAlgorithm,
				atsHashIndexAttribute);

		return unsignedAttributes.add(OID.id_aa_ets_archiveTimestampV3, timeStampAttributeValue);
	}

}
