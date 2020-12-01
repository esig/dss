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
package eu.europa.esig.dss.cades.validation.timestamp;

import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV2;
import static eu.europa.esig.dss.spi.OID.id_aa_ets_archiveTimestampV3;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certificateRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationRefs;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.signature.CadesLevelBaselineLTATimestampExtractor;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampDataBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class CAdESTimestampDataBuilder implements TimestampDataBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESTimestampDataBuilder.class);
	
	private final List<DSSDocument> detachedDocuments;
	private final SignerInformation signerInformation;

	private CMSSignedData cmsSignedData;
	private CadesLevelBaselineLTATimestampExtractor timestampExtractor;
	
	protected CAdESTimestampDataBuilder(final SignerInformation signerInformation, final List<DSSDocument> detachedDocuments) {
		this.signerInformation = signerInformation;
		this.detachedDocuments = detachedDocuments;
	}
	
	public CAdESTimestampDataBuilder(final CMSSignedData cmsSignedData, final SignerInformation signerInformation, 
			List<DSSDocument> detachedDocuments, final CadesLevelBaselineLTATimestampExtractor timestampExtractor) {
		this.cmsSignedData = cmsSignedData;
		this.signerInformation = signerInformation;
		this.detachedDocuments = detachedDocuments;
		this.timestampExtractor = timestampExtractor;
	}
	
	@Override
	public DSSDocument getContentTimestampData(TimestampToken timestampToken) {
		return getOriginalDocument();
	}

	@Override
	public DSSDocument getSignatureTimestampData(TimestampToken timestampToken) {
		byte[] signature = signerInformation.getSignature();
		return new InMemoryDocument(signature);
	}

	@Override
	public DSSDocument getTimestampX1Data(TimestampToken timestampToken) {
		try (ByteArrayOutputStream data = new ByteArrayOutputStream()) {
			data.write(signerInformation.getSignature());
			// We don't include the outer SEQUENCE, only the attrType and
			// attrValues as stated by the TS Â§6.3.5, NOTE 2

			final Attribute attribute = CMSUtils.getUnsignedAttribute(signerInformation, id_aa_signatureTimeStampToken);
			if (attribute != null) {
				data.write(DSSASN1Utils.getDEREncoded(attribute.getAttrType()));
				data.write(DSSASN1Utils.getDEREncoded(attribute.getAttrValues()));
			}
			// Method is common to Type 1 and Type 2
			data.write(getTimestampX2DataBytes(timestampToken));
			byte[] byteArray = data.toByteArray();
			return new InMemoryDocument(byteArray);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public DSSDocument getTimestampX2Data(final TimestampToken timestampToken) {
		byte[] timestampX2DataBytes = getTimestampX2DataBytes(timestampToken);
		return new InMemoryDocument(timestampX2DataBytes);
	}
	
	private byte[] getTimestampX2DataBytes(final TimestampToken timestampToken) {
		try (ByteArrayOutputStream data = new ByteArrayOutputStream()) {
			// Those are common to Type 1 and Type 2
			final Attribute certAttribute = CMSUtils.getUnsignedAttribute(signerInformation, id_aa_ets_certificateRefs);
			final Attribute revAttribute = CMSUtils.getUnsignedAttribute(signerInformation, id_aa_ets_revocationRefs);
			if (certAttribute != null) {
				data.write(DSSASN1Utils.getDEREncoded(certAttribute.getAttrType()));
				data.write(DSSASN1Utils.getDEREncoded(certAttribute.getAttrValues()));
			}
			if (revAttribute != null) {
				data.write(DSSASN1Utils.getDEREncoded(revAttribute.getAttrType()));
				data.write(DSSASN1Utils.getDEREncoded(revAttribute.getAttrValues()));
			}

			return data.toByteArray();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public DSSDocument getArchiveTimestampData(final TimestampToken timestampToken) throws DSSException {

		final ArchiveTimestampType archiveTimestampType = timestampToken.getArchiveTimestampType();
		DSSDocument archiveTimestampData;
		switch (archiveTimestampType) {
		case CAdES_V2:
			/**
			 * There is a difference between message imprint calculation in ETSI TS 101 733 version 1.8.3 and version 2.2.1.
			 * So we first check the message imprint according to 2.2.1 version and then if it fails get the message imprint
			 * data for the 1.8.3 version message imprint calculation. 
			 */
			archiveTimestampData = getArchiveTimestampDataV2(timestampToken, true);
			if (!timestampToken.matchData(archiveTimestampData, true)) {
				if (LOG.isDebugEnabled()) {
					LOG.debug("Unable to match message imprint for an Archive TimestampToken V2 with Id '{}' "
							+ "by including unsigned attribute tags and length, try to compute the data without...", timestampToken.getDSSIdAsString());
				}
				archiveTimestampData = getArchiveTimestampDataV2(timestampToken, false);
			}
			break;
		case CAdES_V3:
			archiveTimestampData = getArchiveTimestampDataV3(timestampToken);
			break;
		default:
			throw new DSSException("Unsupported ArchiveTimestampType " + archiveTimestampType);
		}
		return archiveTimestampData;
	}

	private DSSDocument getArchiveTimestampDataV3(final TimestampToken timestampToken) throws DSSException {

		final Attribute atsHashIndexAttribute = timestampExtractor.getVerifiedAtsHashIndex(signerInformation, timestampToken);

        final DigestAlgorithm messageImprintDigestAlgorithm = timestampToken.getMessageImprint().getAlgorithm();
        byte[] originalDocumentDigest = getOriginalDocumentDigest(messageImprintDigestAlgorithm);
        if (originalDocumentDigest != null) {
            byte[] archiveTimestampDataV3 = timestampExtractor.getArchiveTimestampDataV3(signerInformation, atsHashIndexAttribute, originalDocumentDigest);
            return new InMemoryDocument(archiveTimestampDataV3);
        }
		LOG.error("The original document is not found for TimestampToken with Id '{}'! "
				+ "Unable to compute message imprint.", timestampToken.getDSSIdAsString());
        return null;
	}
	
	private byte[] getOriginalDocumentDigest(DigestAlgorithm algo) {
		DSSDocument originalDocument = getOriginalDocument();
		if (originalDocument != null) {
			return Utils.fromBase64(originalDocument.getDigest(algo));
		} else {
			return null;
		}
	}
	
	/**
	 * There is a difference in ETSI TS 101 733 version 1.8.3 and version 2.2.1 in archive-timestamp-v2 hash calculation.
	 * In the 1.8.3 version the calculation did not include the tag and the length octets of the unsigned attributes set.
	 * The hash calculation is described in Annex K in both versions of ETSI TS 101 733.
	 * The differences are in TableK.3: Signed Data in rows 22 and 23.
	 * However, there is a note in 2.2.1 version (Annex K, Table K.3: SignedData, Note 3) that says:
	 * "A previous version of CAdES did not include the tag and length octets of this SET OF type
	 * of unsignedAttrs element in this annex, which contradicted the normative section. To maximize
	 * interoperability, it is recommended to simultaneously compute the two hash values
	 * (including and not including the tag and length octets of SET OF type) and to test
	 * the value of the timestamp against both."
	 * The includeUnsignedAttrsTagAndLength parameter decides whether the tag and length octets are included.
	 * 
	 * According to RFC 5652 it is possible to use DER or BER encoding for SignedData structure.
	 * The exception is the signed attributes attribute and authenticated attributes attributes which
	 * have to be DER encoded. 
	 * 
	 * @param timestampToken
	 * @param includeUnsignedAttrsTagAndLength
	 * @return
	 * @throws DSSException
	 */
	private DSSDocument getArchiveTimestampDataV2(TimestampToken timestampToken, boolean includeUnsignedAttrsTagAndLength) throws DSSException {

		try (ByteArrayOutputStream data = new ByteArrayOutputStream()) {

			final ContentInfo contentInfo = cmsSignedData.toASN1Structure();
			final SignedData signedData = SignedData.getInstance(contentInfo.getContent());
			
			byte[] contentInfoBytes = getContentInfoBytes(signedData);
			data.write(contentInfoBytes);
			
			if (CMSUtils.isDetachedSignature(cmsSignedData)) {
				byte[] originalDocumentBinaries = getOriginalDocumentBinaries();
				if (originalDocumentBinaries == null) {
					LOG.warn("The detached content is not provided for a TimestampToken with Id '{}'. "
							+ "Not possible to compute message imprint!", timestampToken.getDSSIdAsString());
					return null;
				}
				data.write(originalDocumentBinaries);
			}
			
			byte[] certificateBytes = getCertificateDataBytes(signedData);
			if (Utils.isArrayNotEmpty(certificateBytes)) {
				data.write(certificateBytes);
			}
			
			byte[] crlDataBytes = getCRLDataBytes(signedData);
			if (Utils.isArrayNotEmpty(crlDataBytes)) {
				data.write(crlDataBytes);
			}

			final SignerInfo signerInfo = signerInformation.toASN1Structure();
			byte[] signerInfoBytes = getSignerInfoBytes(timestampToken, includeUnsignedAttrsTagAndLength, signerInfo);
			data.write(signerInfoBytes);

			final byte[] result = data.toByteArray();
			return new InMemoryDocument(result);
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (Exception e) {
			// When error in computing or in format the algorithm just continues.
			LOG.error("An error in computing of message impring for a TimestampToken with Id : {}. Reason : {}", 
					timestampToken.getDSSIdAsString(), e.getMessage(), e);
			return null;
		}
	}
	
	private byte[] getContentInfoBytes(final SignedData signedData) {
		final ContentInfo content = signedData.getEncapContentInfo();
		byte[] contentInfoBytes;
		if (content.getContent() instanceof BEROctetString) {
			contentInfoBytes = DSSASN1Utils.getBEREncoded(content);
		} else {
			contentInfoBytes = DSSASN1Utils.getDEREncoded(content);
		}
		if (LOG.isTraceEnabled()) {
			LOG.trace("Content Info: {}", DSSUtils.toHex(contentInfoBytes));
		}
		return contentInfoBytes;
	}
	
	private byte[] getOriginalDocumentBinaries() {
		/*
		 * Detached signatures have either no encapContentInfo in signedData, or it
		 * exists but has no eContent
		 */
		DSSDocument originalDocument = getOriginalDocument();
		if (originalDocument != null) {
			return DSSUtils.toByteArray(getOriginalDocument());
		}
		return null;
	}
	
	private byte[] getCertificateDataBytes(final SignedData signedData) throws IOException {
		byte[] certificatesBytes = null;
		
		final ASN1Set certificates = signedData.getCertificates();
		if (certificates != null) {
			/*
			 * In order to calculate correct message imprint it is important
			 * to use the correct encoding.
			 */
			if (certificates instanceof BERSet) {
				certificatesBytes = new BERTaggedObject(false, 0, new BERSequence(certificates.toArray())).getEncoded();
			} else {
				certificatesBytes = new DERTaggedObject(false, 0, new DERSequence(certificates.toArray())).getEncoded();
			}
			
			if (LOG.isTraceEnabled()) {
				LOG.trace("Certificates: {}", DSSUtils.toHex(certificatesBytes));
			}
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("Certificates are not present in the SignedData.");
		}
		return certificatesBytes;
	}
	
	private byte[] getCRLDataBytes(final SignedData signedData) throws IOException {
		byte[] crlBytes = null;
		
		final ASN1Set crLs = signedData.getCRLs();
		if (crLs != null) {
			
			if (signedData.getCRLs() instanceof BERSet) {
				crlBytes = new BERTaggedObject(false, 1, new BERSequence(crLs.toArray())).getEncoded();
			} else {
				crlBytes = new DERTaggedObject(false, 1, new DERSequence(crLs.toArray())).getEncoded();
			}
			if (LOG.isTraceEnabled()) {
				LOG.trace("CRLs: {}", DSSUtils.toHex(crlBytes));
			}
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("CRLs are not present in the SignedData.");
		}
		return crlBytes;
	}
	
	private byte[] getSignerInfoBytes(final TimestampToken timestampToken, boolean includeUnsignedAttrsTagAndLength, 
			final SignerInfo signerInfo) throws IOException {
		try (ByteArrayOutputStream signerByteArrayOutputStream = new ByteArrayOutputStream()) {
			
			final ASN1Set unauthenticatedAttributes = signerInfo.getUnauthenticatedAttributes();
			final ASN1Sequence filteredUnauthenticatedAttributes = filterUnauthenticatedAttributes(unauthenticatedAttributes, timestampToken);
			final ASN1Sequence asn1Object = getSignerInfoEncoded(signerInfo, filteredUnauthenticatedAttributes, includeUnsignedAttrsTagAndLength);
			for (int ii = 0; ii < asn1Object.size(); ii++) {
				final byte[] signerInfoBytes = DSSASN1Utils.getDEREncoded(asn1Object.getObjectAt(ii).toASN1Primitive());
				signerByteArrayOutputStream.write(signerInfoBytes);
			}
			final byte[] signerInfoBytes = signerByteArrayOutputStream.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("SignerInfoBytes: {}", DSSUtils.toHex(signerInfoBytes));
			}
			return signerInfoBytes;
			
		}
	}

	/**
	 * Remove any archive-timestamp-v2/3 attribute added after the
	 * timestampToken
	 */
	private ASN1Sequence filterUnauthenticatedAttributes(ASN1Set unauthenticatedAttributes, TimestampToken timestampToken) {
		ASN1EncodableVector result = new ASN1EncodableVector();
		for (int ii = 0; ii < unauthenticatedAttributes.size(); ii++) {

			final Attribute attribute = Attribute.getInstance(unauthenticatedAttributes.getObjectAt(ii));
			final ASN1ObjectIdentifier attrType = attribute.getAttrType();
			if (id_aa_ets_archiveTimestampV2.equals(attrType) || id_aa_ets_archiveTimestampV3.equals(attrType)) {
				try {

					TimeStampToken token = DSSASN1Utils.getTimeStampToken(attribute);
					if (!token.getTimeStampInfo().getGenTime().before(timestampToken.getGenerationTime())) {
						continue;
					}
				} catch (Exception e) {
					throw new DSSException(e);
				}
			}
			result.add(unauthenticatedAttributes.getObjectAt(ii));
		}
		return new DERSequence(result);
	}

	/**
	 * Copied from org.bouncycastle.asn1.cms.SignerInfo#toASN1Object() and
	 * adapted to be able to use the custom unauthenticatedAttributes
	 * 
	 * There is a difference in ETSI TS 101 733 version 1.8.3 and version 2.2.1 in archive-timestamp-v2 hash calculation.
	 * In the 1.8.3 version the calculation did not include the tag and the length octets of the unsigned attributes set.
	 * The hash calculation is described in Annex K in both versions of ETSI TS 101 733.
	 * The differences are in TableK.3: Signed Data in rows 22 and 23.
	 * However, there is a note in 2.2.1 version (Annex K, Table K.3: SignedData, Note 3) that says:
	 * "A previous version of CAdES did not include the tag and length octets of this SET OF type
	 * of unsignedAttrs element in this annex, which contradicted the normative section. To maximize
	 * interoperability, it is recommended to imultaneously compute the two hash values
	 * (including and not including the tag and length octets of SET OF type) and to test
	 * the value of the timestamp against both."
	 * The includeUnsignedAttrsTagAndLength parameter decides whether the tag and length octets are included.
	 *
	 * @param signerInfo
	 * @param signerInfo
	 * @param unauthenticatedAttributes
	 * @param includeUnsignedAttrsTagAndLength
	 * @return
	 */
	private ASN1Sequence getSignerInfoEncoded(final SignerInfo signerInfo, final ASN1Sequence unauthenticatedAttributes, final boolean includeUnsignedAttrsTagAndLength) {

		ASN1EncodableVector v = new ASN1EncodableVector();

		v.add(signerInfo.getVersion());
		v.add(signerInfo.getSID());
		v.add(signerInfo.getDigestAlgorithm());

		final DERTaggedObject signedAttributes = CMSUtils.getDERSignedAttributes(signerInformation);
		if (signedAttributes != null) {
			v.add(signedAttributes);
		}

		v.add(signerInfo.getDigestEncryptionAlgorithm());
		v.add(signerInfo.getEncryptedDigest());

		if (unauthenticatedAttributes != null) {
			if (includeUnsignedAttrsTagAndLength) {
				v.add(new DERTaggedObject(false, 1, unauthenticatedAttributes));
			} else {
				for (int i = 0; i < unauthenticatedAttributes.size(); i++) {
					v.add(unauthenticatedAttributes.getObjectAt(i));
				}
			}
		}
		
		return new DERSequence(v);
	}
	
	private DSSDocument getOriginalDocument() {
		try {
			return CMSUtils.getOriginalDocument(cmsSignedData, detachedDocuments);
		} catch (DSSException e) {
			LOG.error("Cannot extract original document! Reason : {}", e.getMessage());
			return null;
		}
	}

}
