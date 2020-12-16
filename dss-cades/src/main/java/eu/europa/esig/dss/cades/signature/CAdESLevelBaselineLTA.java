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
import eu.europa.esig.dss.cades.TimeStampTokenProductionComparator;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;
import eu.europa.esig.dss.validation.ValidationDataForInclusionBuilder;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

import static eu.europa.esig.dss.spi.OID.id_aa_ATSHashIndex;
import static eu.europa.esig.dss.spi.OID.id_aa_ATSHashIndexV3;

/**
 * This class holds the CAdES-A signature profiles; it supports the later, over time _extension_ of a signature with
 * id-aa-ets-archiveTimestampV2 attributes as defined in ETSI TS 101 733 V1.8.1, clause 6.4.1.
 *
 * "If the certificate-values and revocation-values attributes are not present in the CAdES-BES or CAdES-EPES, then they
 * shall be added to the electronic signature prior to computing the archive time-stamp token." is the reason we extend
 * from the XL profile.
 *
 */
public class CAdESLevelBaselineLTA extends CAdESLevelBaselineLT {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESLevelBaselineLTA.class);

	/**
	 * The default constructor
	 *
	 * @param tspSource {@link TSPSource} to request a timestamp
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public CAdESLevelBaselineLTA(TSPSource tspSource, CertificateVerifier certificateVerifier) {
		super(tspSource, certificateVerifier);
	}

	@Override
	protected CMSSignedData preExtendCMSSignedData(CMSSignedData cmsSignedData, CAdESSignatureParameters parameters) {
		/*
		 * ETSI EN 319 122-1 V1.1.1 (2016-04), chapter "5.5.3 The archive-time-stamp-v3 attribute":
		 * 
		 * The present document specifies two strategies for the inclusion of validation data, 
		 * depending on whether attributes for long term availability, as defined in different 
		 * versions of ETSI TS 101 733 [1], have already been added to the SignedData:
		 * 
		 * - If none of ATSv2 attributes (see clause A.2.4), or an earlier form of archive time-stamp as defined in ETSI
		 *   TS 101 733 [1] or long-term-validation (see clause A.2.5) attributes is already present in any
		 *   SignerInfo of the root SignedData, then the new validation material shall be included within the root
		 *   SignedData.certificates, or SignedData.crls as applicable.
		 */
		if (!includesATSv2(cmsSignedData)) {
			for (SignerInformation signerInformation : cmsSignedData.getSignerInfos().getSigners()) {
				signerInformation = super.extendSignerInformation(cmsSignedData, signerInformation, parameters);
				cmsSignedData = super.extendCMSSignedData(cmsSignedData, signerInformation, parameters);
			}
		}
		return cmsSignedData;
	}

	@Override
	protected SignerInformation extendSignerInformation(CMSSignedData cmsSignedData, SignerInformation signerInformation,
			final CAdESSignatureParameters parameters) throws DSSException {
		signerInformation = super.extendSignerInformation(cmsSignedData, signerInformation, parameters);
		
		/*
		 * If non ATSv2 is present, then the root SignedData is extended in {@code preExtendCMSSignedData(cmsSignedData, parameters)} method
		 */
		AttributeTable unsignedAttributes = CMSUtils.getUnsignedAttributes(signerInformation);
		
		/* 
		 * - If an ATSv2, or other earlier form of archive time-stamp or a long-term-validation attribute, is
		 *   present in any SignerInfo of the root SignedData then the root SignedData.certificates and
         *   SignedData.crls contents shall not be modified. The new validation material shall be provided within 
         *   the TimeStampToken of the latest archive time-stamp (which can be an ATSv2 as defined in 
         *   ETSI TS 101 733 [1], or an ATSv3) or within the latest long-term-validation attribute 
         *   (defined in ETSI TS 101 733 [1]) already contained in the SignerInfo ...
		 */
		if (includesATSv2(cmsSignedData)) {
			try {
				// add missing validation data to the previous (last) ArchiveTimestamp
				CAdESSignature cadesSignature = newCAdESSignature(cmsSignedData, signerInformation, parameters.getDetachedContents());
				ValidationDataForInclusionBuilder validationDataForInclusionBuilder = getValidationDataForInclusionBuilder(cadesSignature)
						.excludeCertificateTokens(cadesSignature.getCompleteCertificateSource().getAllCertificateTokens())
						.excludeCRLs(cadesSignature.getCompleteCRLSource().getAllRevocationBinaries())
						.excludeOCSPs(cadesSignature.getCompleteOCSPSource().getAllRevocationBinaries());
				ValidationDataForInclusion validationDataForInclusion = validationDataForInclusionBuilder.build();
				unsignedAttributes = addValidationData(unsignedAttributes, validationDataForInclusion, parameters.getDetachedContents());
				signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
			} catch (IOException | CMSException | TSPException e) {
				LOG.warn("Validation data to a timestamp was not added due the error : {}", e.getMessage());
			}
		}

		CAdESSignature cadesSignature = newCAdESSignature(cmsSignedData, signerInformation, parameters.getDetachedContents());
		
		unsignedAttributes = addArchiveTimestampV3Attribute(cadesSignature, signerInformation, parameters, unsignedAttributes);
		return SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
	}
	
	@Override
	protected CMSSignedData extendCMSSignedData(CMSSignedData cmsSignedData, SignerInformation signerInformation,
			CAdESSignatureParameters parameters) {
		// post extension is not required for LTA level
		return cmsSignedData;
	}
	
	private AttributeTable addValidationData(AttributeTable unsignedAttributes, final ValidationDataForInclusion validationDataForInclusion,
			final List<DSSDocument> detachedContents) throws IOException, CMSException, TSPException {
		TimeStampToken timestampTokenToExtend = getLastArchiveTimestamp(unsignedAttributes);
		if (timestampTokenToExtend != null) {
			CMSSignedData timestampCMSSignedData = timestampTokenToExtend.toCMSSignedData();
			CMSSignedData extendedTimestampCMSSignedData = extendWithValidationData(
					timestampCMSSignedData, validationDataForInclusion, detachedContents);
					
			unsignedAttributes = replaceTimeStampAttribute(unsignedAttributes, timestampCMSSignedData, extendedTimestampCMSSignedData);
		}
		return unsignedAttributes;
	}
	
	private TimeStampToken getLastArchiveTimestamp(AttributeTable unsignedAttributes) {
		TimeStampToken lastTimeStampToken = null;
		TimeStampTokenProductionComparator comparator = new TimeStampTokenProductionComparator();
		for (TimeStampToken timeStampToken : DSSASN1Utils.findArchiveTimeStampTokens(unsignedAttributes)) {
			if (lastTimeStampToken == null || comparator.after(timeStampToken, lastTimeStampToken)) {
				lastTimeStampToken = timeStampToken; 
			}
		}
		return lastTimeStampToken;
	}
	
	/**
	 * Returns a new {@code AttributeTable} with a replaced {@code attributeToReplace} by {@code attributeToAdd} 
	 * 
	 * @param attributeTable {@link AttributeTable} to replace value in
	 * @param attributeToReplace {@link CMSSignedData} to be replaced
	 * @param attributeToAdd {@link CMSSignedData} to replace by
	 * @return a new {@link AttributeTable}
	 * @throws IOException in case of encoding error
	 * @throws CMSException in case of CMSException
	 */
	private AttributeTable replaceTimeStampAttribute(AttributeTable attributeTable, CMSSignedData attributeToReplace, 
			CMSSignedData attributeToAdd) throws IOException, CMSException {
		ASN1EncodableVector newAsn1EncodableVector = new ASN1EncodableVector();
		Attribute[] attributes = attributeTable.toASN1Structure().getAttributes();
		for (Attribute attribute : attributes) {
			Attribute attibuteToAdd = attribute;
			if (DSSASN1Utils.isArchiveTimeStampToken(attribute)) {
				try {
					// ContentInfo binaries have to be compared, therefore CMSSignedData creation is required
					CMSSignedData cmsSignedData = DSSASN1Utils.getCMSSignedData(attribute);
					if (CMSUtils.isCMSSignedDataEqual(attributeToReplace, cmsSignedData)) {
						ASN1Primitive asn1Primitive = DSSASN1Utils.toASN1Primitive(attributeToAdd.getEncoded());
						attibuteToAdd = new Attribute(attribute.getAttrType(), new DERSet(asn1Primitive));
					}
				} catch (Exception e) {
					LOG.warn("Unable to build a CMSSignedData object from an unsigned attribute. Reason : {}", e.getMessage(), e);
					// we free to continue with the original object, 
					// because it would not be possible to extend the attribute anyway
				}
			}
			newAsn1EncodableVector.add(attibuteToAdd);
		}
		return new AttributeTable(newAsn1EncodableVector);		
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
	 * @param cadesSignature {@link CAdESSignature}
	 * @param signerInformation {@link SignerInformation}
	 * @param parameters {@link CAdESSignatureParameters}
	 * @param unsignedAttributes {@link AttributeTable}
	 */
	private AttributeTable addArchiveTimestampV3Attribute(CAdESSignature cadesSignature, SignerInformation signerInformation,
			CAdESSignatureParameters parameters, AttributeTable unsignedAttributes) {

		final CadesLevelBaselineLTATimestampExtractor timestampExtractor = new CadesLevelBaselineLTATimestampExtractor(cadesSignature);
		final DigestAlgorithm timestampDigestAlgorithm = parameters.getArchiveTimestampParameters().getDigestAlgorithm();
		byte[] originalDocumentDigest = Utils.fromBase64(cadesSignature.getOriginalDocument().getDigest(timestampDigestAlgorithm));

		ASN1ObjectIdentifier atsHashIndexTableIdentifier = getAtsHashIndexTableIdentifier(parameters);
		final Attribute atsHashIndexAttribute = timestampExtractor.getAtsHashIndex(signerInformation, timestampDigestAlgorithm, atsHashIndexTableIdentifier);

		final byte[] encodedToTimestamp = timestampExtractor.getArchiveTimestampDataV3(signerInformation, atsHashIndexAttribute, originalDocumentDigest);

		final ASN1Object timeStampAttributeValue = getTimeStampAttributeValue(encodedToTimestamp, timestampDigestAlgorithm,
				atsHashIndexAttribute);

		return unsignedAttributes.add(OID.id_aa_ets_archiveTimestampV3, timeStampAttributeValue);
	}
	
	private ASN1ObjectIdentifier getAtsHashIndexTableIdentifier(CAdESSignatureParameters signatureParameters) {
		if (!signatureParameters.isEn319122()) {
			return id_aa_ATSHashIndex;
		} else {
			return id_aa_ATSHashIndexV3;
		}
	}
	
	private boolean includesATSv2(CMSSignedData cmsSignedData) {
		for (SignerInformation signerInformation : cmsSignedData.getSignerInfos()) {
			if (CMSUtils.containsATSTv2(signerInformation)) {
				return true;
			}
		}
		return false;
	}

}
