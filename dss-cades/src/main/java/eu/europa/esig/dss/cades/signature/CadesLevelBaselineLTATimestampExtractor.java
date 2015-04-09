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

import static eu.europa.esig.dss.OID.id_aa_ATSHashIndex;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certValues;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationValues;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Extracts the necessary information to compute the CAdES Archive Timestamp V3.
 *
 *
 *
 *
 *
 */
public class CadesLevelBaselineLTATimestampExtractor {

	private static final Logger LOG = LoggerFactory.getLogger(CadesLevelBaselineLTATimestampExtractor.class);
	public static final DigestAlgorithm DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO = DigestAlgorithm.SHA256;
	/**
	 * If the algorithm identifier in ATSHashIndex has the default value (DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO) then it can be omitted.
	 */
	private static final boolean OMIT_ALGORITHM_IDENTIFIER_IF_DEFAULT = true;

	/**
	 * The field hashIndAlgorithm contains an identifier of the hash algorithm used to compute the hash values
	 * contained in certificatesHashIndex, crlsHashIndex, and unsignedAttrsHashIndex. This algorithm
	 * shall be the same as the hash algorithm used for computing the archive time-stamp’s message imprint.
	 *
	 * hashIndAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
	 */
	private DigestAlgorithm hashIndexDigestAlgorithm;

	private final Set<ASN1ObjectIdentifier> excludedAttributesFromAtsHashIndex = new HashSet<ASN1ObjectIdentifier>();
	private CAdESSignature cadesSignature;

	/**
	 * This is the default constructor for the {@code CadesLevelBaselineLTATimestampExtractor}.
	 *
	 * @param cadesSignature {@code CAdESSignature} related to the archive timestamp
	 */
	public CadesLevelBaselineLTATimestampExtractor(final CAdESSignature cadesSignature) {

		this.cadesSignature = cadesSignature;
		/* these attribute are validated elsewhere */
		excludedAttributesFromAtsHashIndex.add(id_aa_ets_certValues);
		excludedAttributesFromAtsHashIndex.add(id_aa_ets_revocationValues);
	}

	/**
	 * The ats-hash-index unsigned attribute provides an unambiguous imprint of the essential components of a CAdES
	 * signature for use in the archive time-stamp (see 6.4.3). These essential components are elements of the following ASN.1
	 * SET OF structures: unsignedAttrs, SignedData.certificates, and SignedData.crls.
	 *
	 * The ats-hash-index attribute value has the ASN.1 syntax ATSHashIndex:
	 * ATSHashIndex ::= SEQUENCE {
	 * hashIndAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
	 * certificatesHashIndex SEQUENCE OF OCTET STRING,
	 * crlsHashIndex SEQUENCE OF OCTET STRING,
	 *
	 * @param signerInformation
	 * @return
	 */
	public Attribute getAtsHashIndex(SignerInformation signerInformation, DigestAlgorithm hashIndexDigestAlgorithm) throws DSSException {

		this.hashIndexDigestAlgorithm = hashIndexDigestAlgorithm;
		final AlgorithmIdentifier algorithmIdentifier = getHashIndexDigestAlgorithmIdentifier();
		final ASN1Sequence certificatesHashIndex = getCertificatesHashIndex();
		final ASN1Sequence crLsHashIndex = getCRLsHashIndex();
		final ASN1Sequence unsignedAttributesHashIndex = getUnsignedAttributesHashIndex(signerInformation);
		return getComposedAtsHashIndex(algorithmIdentifier, certificatesHashIndex, crLsHashIndex, unsignedAttributesHashIndex);
	}

	/**
	 * get the atsHash index for verification of the provided token.
	 *
	 * @param signerInformation
	 * @param timestampToken
	 * @return
	 */
	public Attribute getVerifiedAtsHashIndex(SignerInformation signerInformation, TimestampToken timestampToken) throws DSSException {

		final AlgorithmIdentifier derObjectAlgorithmIdentifier = getAlgorithmIdentifier(timestampToken);
		final ASN1Sequence certificatesHashIndex = getVerifiedCertificatesHashIndex(timestampToken);
		final ASN1Sequence crLsHashIndex = getVerifiedCRLsHashIndex(timestampToken);
		final ASN1Sequence unsignedAttributesHashIndex = getVerifiedUnsignedAttributesHashIndex(signerInformation, timestampToken);
		return getComposedAtsHashIndex(derObjectAlgorithmIdentifier, certificatesHashIndex, crLsHashIndex, unsignedAttributesHashIndex);
	}

	private Attribute getComposedAtsHashIndex(AlgorithmIdentifier algorithmIdentifiers, ASN1Sequence certificatesHashIndex, ASN1Sequence crLsHashIndex,
			ASN1Sequence unsignedAttributesHashIndex) {
		final ASN1EncodableVector vector = new ASN1EncodableVector();
		if (algorithmIdentifiers != null) {
			vector.add(algorithmIdentifiers);
		}
		vector.add(certificatesHashIndex);
		vector.add(crLsHashIndex);
		vector.add(unsignedAttributesHashIndex);
		final ASN1Sequence derSequence = new DERSequence(vector);
		return new Attribute(id_aa_ATSHashIndex, new DERSet(derSequence));
	}

	/**
	 * The field certificatesHashIndex is a sequence of octet strings. Each one contains the hash value of one
	 * instance of CertificateChoices within certificates field of the root SignedData. A hash value for
	 * every instance of CertificateChoices, as present at the time when the corresponding archive time-stamp is
	 * requested, shall be included in certificatesHashIndex. No other hash value shall be included in this field.
	 *
	 * @return
	 * @throws eu.europa.esig.dss.DSSException
	 */
	private ASN1Sequence getCertificatesHashIndex() throws DSSException {

		final ASN1EncodableVector certificatesHashIndexVector = new ASN1EncodableVector();

		final List<CertificateToken> certificateTokens = cadesSignature.getCertificatesWithinSignatureAndTimestamps();
		for (final CertificateToken certificateToken : certificateTokens) {
			final byte[] encodedCertificate = certificateToken.getEncoded();
			final byte[] digest = DSSUtils.digest(hashIndexDigestAlgorithm, encodedCertificate);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Adding to CertificatesHashIndex DSS-Identifier: {} with hash {}", certificateToken.getDSSId(), Hex.encodeHexString(digest));
			}
			final DEROctetString derOctetStringDigest = new DEROctetString(digest);
			certificatesHashIndexVector.add(derOctetStringDigest);
		}
		return new DERSequence(certificatesHashIndexVector);
	}

	/**
	 * The field certificatesHashIndex is a sequence of octet strings. Each one contains the hash value of one
	 * instance of CertificateChoices within certificates field of the root SignedData. A hash value for
	 * every instance of CertificateChoices, as present at the time when the corresponding archive time-stamp is
	 * requested, shall be included in certificatesHashIndex. No other hash value shall be included in this field.
	 *
	 * @return
	 * @throws eu.europa.esig.dss.DSSException
	 */
	@SuppressWarnings("unchecked")
	private ASN1Sequence getVerifiedCertificatesHashIndex(TimestampToken timestampToken) throws DSSException {

		final ASN1Sequence certHashes = getCertificatesHashIndex(timestampToken);
		final ArrayList<DEROctetString> certHashesList = Collections.list(certHashes.getObjects());

		final List<CertificateToken> certificates = cadesSignature.getCertificatesWithinSignatureAndTimestamps();
		for (final CertificateToken certificateToken : certificates) {

			final byte[] encodedCertificate = certificateToken.getEncoded();
			final byte[] digest = DSSUtils.digest(hashIndexDigestAlgorithm, encodedCertificate);
			final DEROctetString derOctetStringDigest = new DEROctetString(digest);
			if (certHashesList.remove(derOctetStringDigest)) {
				// attribute present in signature and in timestamp
				LOG.debug("Cert {} present in timestamp", certificateToken.getAbbreviation());
			} else {
				LOG.debug("Cert {} not present in timestamp", certificateToken.getAbbreviation());
			}
		}
		if (!certHashesList.isEmpty()) {
			LOG.error("{} attribute hash in Cert Hashes have not been found in document attributes: {}", certHashesList.size(), certHashesList);
			// return a empty DERSequence to screw up the hash
			return new DERSequence();
		}
		return certHashes;
	}

	/**
	 * The field crlsHashIndex is a sequence of octet strings. Each one contains the hash value of one instance of
	 * RevocationInfoChoice within crls field of the root SignedData. A hash value for every instance of
	 * RevocationInfoChoice, as present at the time when the corresponding archive time-stamp is requested, shall be
	 * included in crlsHashIndex. No other hash values shall be included in this field.
	 *
	 * @return
	 * @throws eu.europa.esig.dss.DSSException
	 */
	@SuppressWarnings("unchecked")
	private ASN1Sequence getCRLsHashIndex() throws DSSException {

		final ASN1EncodableVector crlsHashIndex = new ASN1EncodableVector();

		final SignedData signedData = SignedData.getInstance(cadesSignature.getCmsSignedData().toASN1Structure().getContent());
		final ASN1Set signedDataCRLs = signedData.getCRLs();
		if (signedDataCRLs != null) {
			final Enumeration<ASN1Encodable> crLs = signedDataCRLs.getObjects();
			if (crLs != null) {
				while (crLs.hasMoreElements()) {
					final ASN1Encodable asn1Encodable = crLs.nextElement();
					digestAndAddToList(crlsHashIndex, DSSASN1Utils.getDEREncoded(asn1Encodable));
				}
			}
		}

		return new DERSequence(crlsHashIndex);
	}

	private void digestAndAddToList(ASN1EncodableVector crlsHashIndex, byte[] encoded) {
		final byte[] digest = DSSUtils.digest(hashIndexDigestAlgorithm, encoded);
		if (LOG.isDebugEnabled()) {
			LOG.debug("Adding to crlsHashIndex with hash {}", Hex.encodeHexString(digest));
		}
		final DEROctetString derOctetStringDigest = new DEROctetString(digest);
		crlsHashIndex.add(derOctetStringDigest);
	}

	/**
	 * The field crlsHashIndex is a sequence of octet strings. Each one contains the hash value of one instance of
	 * RevocationInfoChoice within crls field of the root SignedData. A hash value for every instance of
	 * RevocationInfoChoice, as present at the time when the corresponding archive time-stamp is requested, shall be
	 * included in crlsHashIndex. No other hash values shall be included in this field.
	 *
	 * @return
	 * @throws eu.europa.esig.dss.DSSException
	 */
	@SuppressWarnings("unchecked")
	private ASN1Sequence getVerifiedCRLsHashIndex(TimestampToken timestampToken) throws DSSException {

		final ASN1Sequence crlHashes = getCRLHashIndex(timestampToken);
		final ArrayList<DEROctetString> crlHashesList = Collections.list(crlHashes.getObjects());

		final SignedData signedData = SignedData.getInstance(cadesSignature.getCmsSignedData().toASN1Structure().getContent());
		final ASN1Set signedDataCRLs = signedData.getCRLs();
		if (signedDataCRLs != null) {
			final Enumeration<ASN1Encodable> crLs = signedDataCRLs.getObjects();
			if (crLs != null) {
				while (crLs.hasMoreElements()) {
					final ASN1Encodable asn1Encodable = crLs.nextElement();
					handleRevocationEncoded(crlHashesList, DSSASN1Utils.getDEREncoded(asn1Encodable));
				}
			}
		}

		if (!crlHashesList.isEmpty()) {
			LOG.error("{} attribute hash in CRL Hashes have not been found in document attributes: {}", crlHashesList.size(), crlHashesList);
			// return a empty DERSequence to screw up the hash
			return new DERSequence();
		}

		return crlHashes;
	}

	private void handleRevocationEncoded(ArrayList<DEROctetString> crlHashesList, byte[] ocspHolderEncoded) {

		final byte[] digest = DSSUtils.digest(hashIndexDigestAlgorithm, ocspHolderEncoded);
		final DEROctetString derOctetStringDigest = new DEROctetString(digest);
		if (crlHashesList.remove(derOctetStringDigest)) {
			// attribute present in signature and in timestamp
			if (LOG.isDebugEnabled()) {
				LOG.debug("CRL/OCSP present in timestamp {}", DSSUtils.toHex(derOctetStringDigest.getOctets()));
			}
		} else {
			if (LOG.isDebugEnabled()) {
				LOG.debug("CRL/OCSP not present in timestamp {}", DSSUtils.toHex(derOctetStringDigest.getOctets()));
			}
		}
	}

	private boolean handleCrlEncoded(ArrayList<DEROctetString> crlHashesList, byte[] crlHolderEncoded) {
		final byte[] digest = DSSUtils.digest(hashIndexDigestAlgorithm, crlHolderEncoded);
		final DEROctetString derOctetStringDigest = new DEROctetString(digest);

		return crlHashesList.remove(derOctetStringDigest);
	}

	/**
	 * The field unsignedAttrsHashIndex is a sequence of octet strings. Each one contains the hash value of one
	 * instance of Attribute within unsignedAttrs field of the SignerInfo. A hash value for every instance of
	 * Attribute, as present at the time when the corresponding archive time-stamp is requested, shall be included in
	 * unsignedAttrsHashIndex. No other hash values shall be included in this field.
	 *
	 * @param signerInformation
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private ASN1Sequence getUnsignedAttributesHashIndex(SignerInformation signerInformation) throws DSSException {

		final ASN1EncodableVector unsignedAttributesHashIndex = new ASN1EncodableVector();
		AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
		final ASN1EncodableVector asn1EncodableVector = unsignedAttributes.toASN1EncodableVector();
		for (int i = 0; i < asn1EncodableVector.size(); i++) {
			final Attribute attribute = (Attribute) asn1EncodableVector.get(i);
			if (!excludedAttributesFromAtsHashIndex.contains(attribute.getAttrType())) {
				final DEROctetString derOctetStringDigest = getAttributeDerOctetStringHash(attribute);
				unsignedAttributesHashIndex.add(derOctetStringDigest);
			}
		}
		return new DERSequence(unsignedAttributesHashIndex);
	}

	/**
	 * The field unsignedAttrsHashIndex is a sequence of octet strings. Each one contains the hash value of one
	 * instance of Attribute within unsignedAttrs field of the SignerInfo. A hash value for every instance of
	 * Attribute, as present at the time when the corresponding archive time-stamp is requested, shall be included in
	 * unsignedAttrsHashIndex. No other hash values shall be included in this field.
	 *
	 * We check that every hash attribute found in the timestamp token is found if the signerInformation.
	 *
	 * If there is more unsigned attributes in the signerInformation than present in the hash attributes list
	 * (and there is at least the archiveTimestampAttributeV3), we don't report any error nor which attributes are signed by the timestamp.
	 * If there is some attributes that are not present or altered in the signerInformation, we just return some empty sequence to make
	 * sure that the timestamped data will not match. We do not report which attributes hash are present if any.
	 *
	 * If there is not attribute at all in the archive timestamp hash index, that would means we didn't check anything.
	 *
	 * @param signerInformation
	 * @param timestampToken
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private ASN1Sequence getVerifiedUnsignedAttributesHashIndex(SignerInformation signerInformation, TimestampToken timestampToken) throws DSSException {

		final ASN1Sequence unsignedAttributesHashes = getUnsignedAttributesHashIndex(timestampToken);
		final ArrayList<DEROctetString> timestampUnsignedAttributesHashesList = Collections.list(unsignedAttributesHashes.getObjects());

		AttributeTable unsignedAttributes = CAdESSignature.getUnsignedAttributes(signerInformation);
		final ASN1EncodableVector asn1EncodableVector = unsignedAttributes.toASN1EncodableVector();
		for (int i = 0; i < asn1EncodableVector.size(); i++) {
			final Attribute attribute = (Attribute) asn1EncodableVector.get(i);
			final DEROctetString derOctetStringDigest = getAttributeDerOctetStringHash(attribute);
			final ASN1ObjectIdentifier attrType = attribute.getAttrType();
			if (timestampUnsignedAttributesHashesList.remove(derOctetStringDigest)) {
				// attribute present in signature and in timestamp
				LOG.debug("Attribute {} present in timestamp", attrType.getId());
			} else {
				LOG.debug("Attribute {} not present in timestamp", attrType.getId());
			}
		}
		if (!timestampUnsignedAttributesHashesList.isEmpty()) {
			LOG.error("{} attribute hash in Timestamp have not been found in document attributes: {}", timestampUnsignedAttributesHashesList.size(),
					timestampUnsignedAttributesHashesList);
			// return a empty DERSequence to screw up the hash
			return new DERSequence();
		}
		// return the original DERSequence
		return unsignedAttributesHashes;
	}

	private DEROctetString getAttributeDerOctetStringHash(Attribute attribute) throws DSSException {

		final byte[] attributeEncoded = DSSASN1Utils.getDEREncoded(attribute);
		final byte[] digest = DSSUtils.digest(hashIndexDigestAlgorithm, attributeEncoded);
		return new DEROctetString(digest);
	}

	/**
	 * Extract the Unsigned Attribute Archive Timestamp Attribute Hash Index from a timestampToken
	 *
	 * @param timestampToken
	 * @return
	 */
	private ASN1Sequence getUnsignedAttributesHashIndex(TimestampToken timestampToken) {
		final ASN1Sequence timestampAttributeAtsHashIndexValue = getAtsHashIndex(timestampToken);
		int unsignedAttributesIndex = 2;
		if (timestampAttributeAtsHashIndexValue.size() > 3) {
			unsignedAttributesIndex++;
		}
		return (ASN1Sequence) timestampAttributeAtsHashIndexValue.getObjectAt(unsignedAttributesIndex).toASN1Primitive();
	}

	/**
	 * Extract the Unsigned Attribute Archive Timestamp Crl Hash Index from a timestampToken
	 *
	 * @param timestampToken
	 * @return
	 */
	private ASN1Sequence getCRLHashIndex(TimestampToken timestampToken) {
		final ASN1Sequence timestampAttributeAtsHashIndexValue = getAtsHashIndex(timestampToken);
		int crlIndex = 1;
		if (timestampAttributeAtsHashIndexValue.size() > 3) {
			crlIndex++;
		}
		return (ASN1Sequence) timestampAttributeAtsHashIndexValue.getObjectAt(crlIndex).toASN1Primitive();
	}

	/**
	 * Extract the Unsigned Attribute Archive Timestamp Cert Hash Index from a timestampToken
	 *
	 * @param timestampToken
	 * @return
	 */
	private ASN1Sequence getCertificatesHashIndex(TimestampToken timestampToken) {

		final ASN1Sequence timestampAttributeAtsHashIndexValue = getAtsHashIndex(timestampToken);
		int certificateIndex = 0;
		if (timestampAttributeAtsHashIndexValue.size() > 3) {
			certificateIndex++;
		}
		return (ASN1Sequence) timestampAttributeAtsHashIndexValue.getObjectAt(certificateIndex).toASN1Primitive();
	}

	/**
	 * Extract the Unsigned Attribute Archive Timestamp Cert Hash Index from a timestampToken
	 *
	 * @param timestampToken
	 * @return
	 */
	private AlgorithmIdentifier getAlgorithmIdentifier(final TimestampToken timestampToken) {

		final ASN1Sequence timestampAttributeAtsHashIndexValue = getAtsHashIndex(timestampToken);
		if (timestampAttributeAtsHashIndexValue.size() > 3) {

			final int algorithmIndex = 0;
			final ASN1Encodable asn1Encodable = timestampAttributeAtsHashIndexValue.getObjectAt(algorithmIndex);
			if (asn1Encodable instanceof ASN1Sequence) {

				final ASN1Sequence asn1Sequence = (ASN1Sequence) asn1Encodable;
				final ASN1ObjectIdentifier asn1ObjectIdentifier = (ASN1ObjectIdentifier) asn1Sequence.getObjectAt(0);
				hashIndexDigestAlgorithm = DigestAlgorithm.forOID(asn1ObjectIdentifier);
				return AlgorithmIdentifier.getInstance(asn1Sequence);
			} else if (asn1Encodable instanceof DERObjectIdentifier) {

				// TODO (16/11/2014): The relevance and usefulness of the test case must be checked (do the signatures like this exist?)
				ASN1ObjectIdentifier derObjectIdentifier = ASN1ObjectIdentifier.getInstance(asn1Encodable);
				hashIndexDigestAlgorithm = DigestAlgorithm.forOID(derObjectIdentifier.getId());
				return new AlgorithmIdentifier(derObjectIdentifier);
			}
		}
		hashIndexDigestAlgorithm = DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO;
		return null;
	}

	/**
	 * @param timestampToken
	 * @return the content of SignedAttribute: ATS-hash-index unsigned attribute {itu-t(0) identified-organization(4) etsi(0) electronic-signature-standard(1733) attributes(2) 5}
	 */
	private ASN1Sequence getAtsHashIndex(TimestampToken timestampToken) {
		final AttributeTable timestampTokenUnsignedAttributes = timestampToken.getUnsignedAttributes();
		final Attribute atsHashIndexAttribute = timestampTokenUnsignedAttributes.get(id_aa_ATSHashIndex);
		final ASN1Set attrValues = atsHashIndexAttribute.getAttrValues();
		return (ASN1Sequence) attrValues.getObjectAt(0).toASN1Primitive();
	}

	private AlgorithmIdentifier getHashIndexDigestAlgorithmIdentifier() {
		if (OMIT_ALGORITHM_IDENTIFIER_IF_DEFAULT && hashIndexDigestAlgorithm.getOid().equals(DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO.getOid())) {
			return null;
		} else {
			return hashIndexDigestAlgorithm.getAlgorithmIdentifier();
		}
	}

	public byte[] getArchiveTimestampDataV3(SignerInformation signerInformation, Attribute atsHashIndexAttribute, byte[] originalDocument,
			DigestAlgorithm digestAlgorithm) throws DSSException {

		final CMSSignedData cmsSignedData = cadesSignature.getCmsSignedData();
		final byte[] encodedContentType = getEncodedContentType(cmsSignedData); // OID
		final byte[] signedDataDigest = DSSUtils.digest(digestAlgorithm, originalDocument);
		final byte[] encodedFields = getSignedFields(signerInformation);
		final byte[] encodedAtsHashIndex = DSSASN1Utils.getDEREncoded(atsHashIndexAttribute.getAttrValues().getObjectAt(0));
		/** The input for the archive-time-stamp-v3’s message imprint computation shall be the concatenation (in the
		 * order shown by the list below) of the signed data hash (see bullet 2 below) and certain fields in their binary encoded
		 * form without any modification and including the tag, length and value octets:
		 */
		final byte[] dataToTimestamp = DSSUtils.concatenate(encodedContentType, signedDataDigest, encodedFields, encodedAtsHashIndex);
		if (LOG.isDebugEnabled()) {
			LOG.debug("eContentType={}", Hex.encodeHexString(encodedContentType));
			LOG.debug("signedDataDigest={}", Hex.encodeHexString(signedDataDigest));
			LOG.debug("encodedFields=see above");
			LOG.debug("encodedAtsHashIndex={}", Hex.encodeHexString(encodedAtsHashIndex));
			// LOG.debug("Archive Timestamp Data v3 is: {}", Hex.encodeHexString(dataToTimestamp));
		}
		return dataToTimestamp;
	}

	/**
	 * 1) The SignedData.encapContentInfo.eContentType.
	 *
	 * @param cmsSignedData
	 * @return cmsSignedData.getSignedContentTypeOID() as DER encoded
	 */
	private byte[] getEncodedContentType(final CMSSignedData cmsSignedData) {

		final ContentInfo contentInfo = cmsSignedData.toASN1Structure();
		final SignedData signedData = SignedData.getInstance(contentInfo.getContent());
		try {
			return signedData.getEncapContentInfo().getContentType().getEncoded(ASN1Encoding.DER);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * 3) Fields version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, and
	 * signature within the SignedData.signerInfos’s item corresponding to the signature being archive
	 * time-stamped, in their order of appearance.
	 *
	 * @param signerInformation
	 * @return
	 */
	private byte[] getSignedFields(final SignerInformation signerInformation) {

		final SignerInfo signerInfo = signerInformation.toASN1Structure();
		final ASN1Integer version = signerInfo.getVersion();
		final SignerIdentifier sid = signerInfo.getSID();
		final AlgorithmIdentifier digestAlgorithm = signerInfo.getDigestAlgorithm();
		final DERTaggedObject signedAttributes = DSSASN1Utils.getSignedAttributes(signerInformation);
		final AlgorithmIdentifier digestEncryptionAlgorithm = signerInfo.getDigestEncryptionAlgorithm();
		final ASN1OctetString encryptedDigest = signerInfo.getEncryptedDigest();

		final byte[] derEncodedVersion = DSSASN1Utils.getDEREncoded(version);
		final byte[] derEncodedSid = DSSASN1Utils.getDEREncoded(sid);
		final byte[] derEncodedDigestAlgorithm = DSSASN1Utils.getDEREncoded(digestAlgorithm);
		final byte[] derEncodedSignedAttributes = DSSASN1Utils.getDEREncoded(signedAttributes);
		final byte[] derEncodedDigestEncryptionAlgorithm = DSSASN1Utils.getDEREncoded(digestEncryptionAlgorithm);
		final byte[] derEncodedEncryptedDigest = DSSASN1Utils.getDEREncoded(encryptedDigest);
		if (LOG.isDebugEnabled()) {

			LOG.debug("getSignedFields Version={}", Base64.decodeBase64(derEncodedVersion));
			LOG.debug("getSignedFields Sid={}", Base64.decodeBase64(derEncodedSid));
			LOG.debug("getSignedFields DigestAlgorithm={}", Base64.decodeBase64(derEncodedDigestAlgorithm));
			LOG.debug("getSignedFields SignedAttributes={}", Hex.encodeHexString(derEncodedSignedAttributes));
			LOG.debug("getSignedFields DigestEncryptionAlgorithm={}", Base64.decodeBase64(derEncodedDigestEncryptionAlgorithm));
			LOG.debug("getSignedFields EncryptedDigest={}", Base64.decodeBase64(derEncodedEncryptedDigest));
		}
		final byte[] concatenatedArrays = DSSUtils
				.concatenate(derEncodedVersion, derEncodedSid, derEncodedDigestAlgorithm, derEncodedSignedAttributes, derEncodedDigestEncryptionAlgorithm, derEncodedEncryptedDigest);
		return concatenatedArrays;
	}
}
