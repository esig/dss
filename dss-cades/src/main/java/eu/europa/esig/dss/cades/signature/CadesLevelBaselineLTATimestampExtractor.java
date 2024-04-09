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

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static eu.europa.esig.dss.spi.OID.id_aa_ATSHashIndexV2;
import static eu.europa.esig.dss.spi.OID.id_aa_ATSHashIndexV3;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_certValues;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_ets_revocationValues;

/**
 * Extracts the necessary information to compute the CAdES Archive Timestamp V3.
 *
 */
public class CadesLevelBaselineLTATimestampExtractor {

	private static final Logger LOG = LoggerFactory.getLogger(CadesLevelBaselineLTATimestampExtractor.class);
	
	/**
	 * If the algorithm identifier in ATSHashIndex has the default value (DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO) then it
	 * can be omitted.
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

	private final Set<ASN1ObjectIdentifier> excludedAttributesFromAtsHashIndex = new HashSet<>();
	
	private final CMSSignedData cmsSignedData;
	private final Collection<CertificateToken> certificates;

	/**
	 * This is the default constructor for the {@code CadesLevelBaselineLTATimestampExtractor}.
	 *
	 * @param cadesSignature
	 *            {@code CAdESSignature} related to the archive timestamp
	 */
	public CadesLevelBaselineLTATimestampExtractor(final CAdESSignature cadesSignature) {
		this(cadesSignature.getCmsSignedData(), cadesSignature.getCompleteCertificateSource().getCertificates());
		/* these attribute are validated elsewhere */
		excludedAttributesFromAtsHashIndex.add(id_aa_ets_certValues);
		excludedAttributesFromAtsHashIndex.add(id_aa_ets_revocationValues);
	}

	/**
	 * Constructor with a custom collection of certificates
	 *
	 * @param cmsSignedData {@link CMSSignedData}
	 * @param certificates a collection of {@link CertificateToken}s
	 */
	public CadesLevelBaselineLTATimestampExtractor(final CMSSignedData cmsSignedData,
												   final Collection<CertificateToken> certificates) {
		this.cmsSignedData = cmsSignedData;
		this.certificates = certificates;
	}

	/**
	 * The ats-hash-index unsigned attribute provides an unambiguous imprint of the essential components of a CAdES
	 * signature for use in the archive time-stamp (see 6.4.3). These essential components are elements of the following
	 * ASN.1
	 * SET OF structures: unsignedAttrs, SignedData.certificates, and SignedData.crls.
	 *
	 * The ats-hash-index attribute value has the ASN.1 syntax ATSHashIndex:
	 * ATSHashIndex ::= SEQUENCE {
	 * hashIndAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
	 * certificatesHashIndex SEQUENCE OF OCTET STRING,
	 * crlsHashIndex SEQUENCE OF OCTET STRING,
	 *
	 * @param signerInformation {@link SignerInformation}
	 * @param hashIndexDigestAlgorithm {@link DigestAlgorithm}
	 * @param atsHashIndexVersionIdentifier {@link ASN1ObjectIdentifier} version of ats-hash-index to create
	 * @return {@link Attribute} ats-hash-index
	 */
	public Attribute getAtsHashIndex(SignerInformation signerInformation, DigestAlgorithm hashIndexDigestAlgorithm, 
			ASN1ObjectIdentifier atsHashIndexVersionIdentifier) {

		this.hashIndexDigestAlgorithm = hashIndexDigestAlgorithm;
		final AlgorithmIdentifier algorithmIdentifier = getHashIndexDigestAlgorithmIdentifier();
		final ASN1Sequence certificatesHashIndex = getCertificatesHashIndex();
		final ASN1Sequence crLsHashIndex = getCRLsHashIndex();
		final ASN1Sequence unsignedAttributesHashIndex = getUnsignedAttributesHashIndex(signerInformation, atsHashIndexVersionIdentifier);
		return getComposedAtsHashIndex(algorithmIdentifier, certificatesHashIndex, crLsHashIndex, 
				unsignedAttributesHashIndex, atsHashIndexVersionIdentifier);
	}

	/**
	 * get the atsHash index for verification of the provided token.
	 *
	 * @param signerInformation {@link SignerInformation}
	 * @param timestampToken {@link TimestampToken}
	 * @return a re-built ats-hash-index
	 */
	public Attribute getVerifiedAtsHashIndex(SignerInformation signerInformation, TimestampToken timestampToken) {
		final AttributeTable unsignedAttributes = timestampToken.getUnsignedAttributes();
		ASN1ObjectIdentifier atsHashIndexVersionIdentifier = DSSASN1Utils.getAtsHashIndexVersionIdentifier(unsignedAttributes);
		ASN1Sequence atsHashIndex = DSSASN1Utils.getAtsHashIndexByVersion(unsignedAttributes, atsHashIndexVersionIdentifier);
		if (atsHashIndex == null) {
			LOG.warn("A valid atsHashIndex [oid: {}] has not been found for a timestamp with id {}",
					atsHashIndexVersionIdentifier, timestampToken.getDSSIdAsString());
		}
		
		final AlgorithmIdentifier derObjectAlgorithmIdentifier = getAlgorithmIdentifier(atsHashIndex);
		final ASN1Sequence certificatesHashIndex = getVerifiedCertificatesHashIndex(atsHashIndex);
		final ASN1Sequence crLsHashIndex = getVerifiedCRLsHashIndex(atsHashIndex);
		final ASN1Sequence verifiedAttributesHashIndex = getVerifiedUnsignedAttributesHashIndex(signerInformation, atsHashIndex, 
				atsHashIndexVersionIdentifier);
		return getComposedAtsHashIndex(derObjectAlgorithmIdentifier, certificatesHashIndex, crLsHashIndex, 
				verifiedAttributesHashIndex, atsHashIndexVersionIdentifier);
	}

	private Attribute getComposedAtsHashIndex(AlgorithmIdentifier algorithmIdentifiers, ASN1Sequence certificatesHashIndex, ASN1Sequence crLsHashIndex,
			ASN1Sequence unsignedAttributesHashIndex, ASN1ObjectIdentifier atsHashIndexVersionIdentifier) {
		final ASN1EncodableVector vector = new ASN1EncodableVector();
		if (algorithmIdentifiers != null) {
			vector.add(algorithmIdentifiers);
		} else if (id_aa_ATSHashIndexV2.equals(atsHashIndexVersionIdentifier) || id_aa_ATSHashIndexV3.equals(atsHashIndexVersionIdentifier)) {
			// for id_aa_ATSHashIndexV2 and id_aa_ATSHashIndexV3, the algorithmIdentifier is required
			AlgorithmIdentifier sha256AlgorithmIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(DigestAlgorithm.SHA256.getOid()));
			vector.add(sha256AlgorithmIdentifier);
		}
		if (certificatesHashIndex != null) {
			vector.add(certificatesHashIndex);
		}
		if (crLsHashIndex != null) {
			vector.add(crLsHashIndex);
		}
		if (unsignedAttributesHashIndex != null) {
			vector.add(unsignedAttributesHashIndex);
		}
		final ASN1Sequence derSequence = new DERSequence(vector);
		return new Attribute(atsHashIndexVersionIdentifier, new DERSet(derSequence));
	}

	/**
	 * The field certificatesHashIndex is a sequence of octet strings. Each one
	 * contains the hash value of one instance of CertificateChoices within
	 * certificates field of the root SignedData. A hash value for every instance of
	 * CertificateChoices, as present at the time when the corresponding archive
	 * time-stamp is requested, shall be included in certificatesHashIndex. No other
	 * hash value shall be included in this field.
	 *
	 * @return {@link ASN1Sequence}
	 */
	private ASN1Sequence getCertificatesHashIndex() {

		final ASN1EncodableVector certificatesHashIndexVector = new ASN1EncodableVector();

		final Collection<CertificateToken> certificateTokens = certificates;
		for (final CertificateToken certificateToken : certificateTokens) {
			final byte[] digest = certificateToken.getDigest(hashIndexDigestAlgorithm);
			if (LOG.isDebugEnabled()) {
				LOG.debug("Adding to CertificatesHashIndex DSS-Identifier: {} with hash {}", certificateToken.getDSSId(), Utils.toHex(digest));
			}
			final DEROctetString derOctetStringDigest = new DEROctetString(digest);
			certificatesHashIndexVector.add(derOctetStringDigest);
		}
		return new DERSequence(certificatesHashIndexVector);
	}

	/**
	 * The field certificatesHashIndex is a sequence of octet strings. Each one
	 * contains the hash value of one instance of CertificateChoices within
	 * certificates field of the root SignedData. A hash value for every instance of
	 * CertificateChoices, as present at the time when the corresponding archive
	 * time-stamp is requested, shall be included in certificatesHashIndex. No other
	 * hash value shall be included in this field.
	 *
	 * @return {@link ASN1Sequence}
	 */
	private ASN1Sequence getVerifiedCertificatesHashIndex(final ASN1Sequence timestampHashIndex) {

		final ASN1Sequence certHashes = DSSASN1Utils.getCertificatesHashIndex(timestampHashIndex);
		final List<DEROctetString> certHashesList = DSSASN1Utils.getDEROctetStrings(certHashes);

		for (final CertificateToken certificateToken : certificates) {
			final byte[] digest = certificateToken.getDigest(hashIndexDigestAlgorithm);
			final DEROctetString derOctetStringDigest = new DEROctetString(digest);
			if (certHashesList.remove(derOctetStringDigest)) {
				// attribute present in signature and in timestamp
				LOG.debug("Cert {} present in timestamp", certificateToken.getAbbreviation());
			} else {
				LOG.debug("Cert {} not present in timestamp", certificateToken.getAbbreviation());
			}
		}
		if (!certHashesList.isEmpty()) {
			LOG.warn("{} attribute(s) hash in Cert Hashes has not been found in document attributes: {}", certHashesList.size(), certHashesList);
			// return a empty DERSequence to screw up the hash
			return new DERSequence();
		}
		return certHashes;
	}

	/**
	 * The field crlsHashIndex is a sequence of octet strings. Each one contains the
	 * hash value of one instance of RevocationInfoChoice within crls field of the
	 * root SignedData. A hash value for every instance of RevocationInfoChoice, as
	 * present at the time when the corresponding archive time-stamp is requested,
	 * shall be included in crlsHashIndex. No other hash values shall be included in
	 * this field.
	 *
	 * @return {@link ASN1Sequence}
	 */
	@SuppressWarnings("unchecked")
	private ASN1Sequence getCRLsHashIndex() {

		final ASN1EncodableVector crlsHashIndex = new ASN1EncodableVector();

		final SignedData signedData = SignedData.getInstance(cmsSignedData.toASN1Structure().getContent());
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
			LOG.debug("Adding to crlsHashIndex with hash {}", Utils.toHex(digest));
		}
		final DEROctetString derOctetStringDigest = new DEROctetString(digest);
		crlsHashIndex.add(derOctetStringDigest);
	}

	/**
	 * The field crlsHashIndex is a sequence of octet strings. Each one contains the
	 * hash value of one instance of RevocationInfoChoice within crls field of the
	 * root SignedData. A hash value for every instance of RevocationInfoChoice, as
	 * present at the time when the corresponding archive time-stamp is requested,
	 * shall be included in crlsHashIndex. No other hash values shall be included in
	 * this field.
	 *
	 * @return {@link ASN1Sequence}
	 */
	@SuppressWarnings("unchecked")
	private ASN1Sequence getVerifiedCRLsHashIndex(final ASN1Sequence timestampHashIndex) {

		final ASN1Sequence crlHashes = DSSASN1Utils.getCRLHashIndex(timestampHashIndex);
		final List<DEROctetString> crlHashesList = DSSASN1Utils.getDEROctetStrings(crlHashes);

		final SignedData signedData = SignedData.getInstance(cmsSignedData.toASN1Structure().getContent());
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
			LOG.warn("{} attribute(s) hash in CRL Hashes has not been found in document attributes: {}", crlHashesList.size(), crlHashesList);
			// return a empty DERSequence to screw up the hash
			return new DERSequence();
		}

		return crlHashes;
	}

	private void handleRevocationEncoded(List<DEROctetString> crlHashesList, byte[] revocationEncoded) {

		final byte[] digest = DSSUtils.digest(hashIndexDigestAlgorithm, revocationEncoded);
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

	/**
	 * The field unsignedAttrsHashIndex is a sequence of octet strings. Each one contains the hash value of one
	 * instance of Attribute within unsignedAttrs field of the SignerInfo. A hash value for every instance of
	 * Attribute, as present at the time when the corresponding archive time-stamp is requested, shall be included in
	 * unsignedAttrsHashIndex. No other hash values shall be included in this field.
	 *
	 * @param signerInformation {@link SignerInformation}
	 * @param atsHashIndexVersionIdentifier {@link ASN1ObjectIdentifier} of the ats-hash-index table version to create
	 * @return {@link ASN1Sequence}
	 */
	private ASN1Sequence getUnsignedAttributesHashIndex(SignerInformation signerInformation, ASN1ObjectIdentifier atsHashIndexVersionIdentifier) {

		final ASN1EncodableVector unsignedAttributesHashIndex = new ASN1EncodableVector();
		AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
		final ASN1EncodableVector asn1EncodableVector = unsignedAttributes.toASN1EncodableVector();
		for (int i = 0; i < asn1EncodableVector.size(); i++) {
			final Attribute attribute = (Attribute) asn1EncodableVector.get(i);
			if (!excludedAttributesFromAtsHashIndex.contains(attribute.getAttrType())) {
				List<DEROctetString> attributeDerOctetStringHashes = getAttributeDerOctetStringHashes(attribute, atsHashIndexVersionIdentifier);
				for (DEROctetString derOctetStringDigest : attributeDerOctetStringHashes) {
					unsignedAttributesHashIndex.add(derOctetStringDigest);
				}
			}
		}
		return new DERSequence(unsignedAttributesHashIndex);
	}

	/**
	 * The field unsignedAttrsHashIndex is a sequence of octet strings. Each one
	 * contains the hash value of one instance of Attribute within unsignedAttrs
	 * field of the SignerInfo. A hash value for every instance of Attribute, as
	 * present at the time when the corresponding archive time-stamp is requested,
	 * shall be included in unsignedAttrsHashIndex. No other hash values shall be
	 * included in this field.
	 *
	 * We check that every hash attribute found in the timestamp token is found if
	 * the signerInformation.
	 *
	 * If there is more unsigned attributes in the signerInformation than present in
	 * the hash attributes list (and there is at least the
	 * archiveTimestampAttributeV3), we don't report any error nor which attributes
	 * are signed by the timestamp. If there is some attributes that are not present
	 * or altered in the signerInformation, we just return some empty sequence to
	 * make sure that the timestamped data will not match. We do not report which
	 * attributes hash are present if any.
	 *
	 * If there is not attribute at all in the archive timestamp hash index, that
	 * would means we didn't check anything.
	 *
	 * @param signerInformation  {@link SignerInformation}
	 * @param timestampHashIndex {@link ASN1Sequence}
	 * @return {@link ASN1Sequence} unsignedAttributesHashes
	 */
	private ASN1Sequence getVerifiedUnsignedAttributesHashIndex(SignerInformation signerInformation, final ASN1Sequence timestampHashIndex, 
			ASN1ObjectIdentifier atsHashIndexVersionIdentifier) {
		
		final ASN1Sequence unsignedAttributesHashes = DSSASN1Utils.getUnsignedAttributesHashIndex(timestampHashIndex);
		final List<DEROctetString> timestampUnsignedAttributesHashesList = DSSASN1Utils.getDEROctetStrings(unsignedAttributesHashes);
		
		AttributeTable unsignedAttributes = CMSUtils.getUnsignedAttributes(signerInformation);
		final ASN1EncodableVector asn1EncodableVector = unsignedAttributes.toASN1EncodableVector();
		for (int i = 0; i < asn1EncodableVector.size(); i++) {
			final Attribute attribute = (Attribute) asn1EncodableVector.get(i);
			List<DEROctetString> attributeDerOctetStringHashes = getAttributeDerOctetStringHashes(attribute, atsHashIndexVersionIdentifier);
			for (DEROctetString derOctetStringDigest : attributeDerOctetStringHashes) {
				final ASN1ObjectIdentifier attrType = attribute.getAttrType();
				if (timestampUnsignedAttributesHashesList.remove(derOctetStringDigest)) {
					// attribute present in signature and in timestamp
					LOG.debug("Attribute {} present in timestamp", attrType.getId());
				} else {
					LOG.debug("Attribute {} not present in timestamp", attrType.getId());
				}
			}
		}
		if (!timestampUnsignedAttributesHashesList.isEmpty()) {
			LOG.warn("{} attribute(s) hash in Timestamp has not been found in document attributes: {}", timestampUnsignedAttributesHashesList.size(),
					timestampUnsignedAttributesHashesList);
			// return a empty DERSequence to screw up the hash
			return new DERSequence();
		}
		// return the original DERSequence
		return unsignedAttributesHashes;
	}

	private List<DEROctetString> getAttributeDerOctetStringHashes(Attribute attribute, ASN1ObjectIdentifier atsHashIndexVersionIdentifier) {
		List<byte[]> octets = DSSASN1Utils.getOctetStringForAtsHashIndex(attribute, atsHashIndexVersionIdentifier);
		if (Utils.isCollectionNotEmpty(octets)) {
			List<DEROctetString> derOctetStrings = new ArrayList<>();
			for (byte[] bytes : octets) {
				final byte[] digest = DSSUtils.digest(hashIndexDigestAlgorithm, bytes);
				derOctetStrings.add(new DEROctetString(digest));
				if (LOG.isTraceEnabled()) {
					LOG.trace("Digest string [{}] has been added to the hash table", Utils.toHex(digest));
				}
			}
			return derOctetStrings;
		}
		return Collections.emptyList();
	}

	/**
	 * Extract the Unsigned Attribute Archive Timestamp Cert Hash Index from a timestampToken
	 *
	 * @param atsHashIndexValue {@link ASN1Sequence}
	 * @return {@link AlgorithmIdentifier}
	 */
	private AlgorithmIdentifier getAlgorithmIdentifier(final ASN1Sequence atsHashIndexValue) {
		AlgorithmIdentifier algorithmIdentifier = DSSASN1Utils.getAlgorithmIdentifier(atsHashIndexValue);
		hashIndexDigestAlgorithm = algorithmIdentifier != null ? 
				DigestAlgorithm.forOID(algorithmIdentifier.getAlgorithm().getId()) : CMSUtils.DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO;
		return algorithmIdentifier;
	}

	private AlgorithmIdentifier getHashIndexDigestAlgorithmIdentifier() {
		if (OMIT_ALGORITHM_IDENTIFIER_IF_DEFAULT && hashIndexDigestAlgorithm.getOid().equals(CMSUtils.DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO.getOid())) {
			return null;
		} else {
			return DSSASN1Utils.getAlgorithmIdentifier(hashIndexDigestAlgorithm);
		}
	}

	/**
	 * Computes a message-imprint for an archive-time-stamp-v3
	 *
	 * @param signerInformation {@link SignerInformation}
	 * @param atsHashIndexAttribute {@link Attribute}
	 * @param originalDocument {@link DSSDocument} signed document
	 * @param digestAlgorithm {@link DigestAlgorithm} to compute message-digest with
	 * @return {@link DSSMessageDigest} message-imprint digest
	 */
	public DSSMessageDigest getArchiveTimestampV3MessageImprint(
			SignerInformation signerInformation, Attribute atsHashIndexAttribute, DSSDocument originalDocument,
			DigestAlgorithm digestAlgorithm) {
		/*
		 * The input for the archive-time-stamp-v3’s message imprint computation shall be the concatenation (in the
		 * order shown by the list below) of the signed data hash (see bullet 2 below) and certain fields in their
		 * binary encoded
		 * form without any modification and including the tag, length and value octets:
		 */
		final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
		byte[] bytes = null;
		if (LOG.isDebugEnabled()) {
			LOG.debug("Archive Timestamp Data v3 is:");
		}

		bytes = getEncodedContentType(cmsSignedData); // OID
		digestCalculator.update(bytes);
		if (LOG.isDebugEnabled()) {
			LOG.debug("eContentType={}", bytes != null ? Utils.toHex(bytes) : bytes);
		}

		bytes = originalDocument.getDigestValue(digestAlgorithm);
		digestCalculator.update(bytes);
		if (LOG.isDebugEnabled()) {
			LOG.debug("signedDataDigest={}", bytes != null ? Utils.toHex(bytes) : bytes);
		}

		if (LOG.isDebugEnabled()) {
			LOG.debug("encodedFields:");
		}
		writeSignedFields(signerInformation, digestCalculator);
		if (LOG.isDebugEnabled()) {
			LOG.debug("encodedFields end");
		}

		bytes = DSSASN1Utils.getDEREncoded(atsHashIndexAttribute.getAttrValues().getObjectAt(0));
		digestCalculator.update(bytes);
		if (LOG.isDebugEnabled()) {
			LOG.debug("encodedAtsHashIndex={}", bytes != null ? Utils.toHex(bytes) : bytes);
		}

		return digestCalculator.getMessageDigest();
	}

	/**
	 * 1) The SignedData.encapContentInfo.eContentType.
	 *
	 * @param cmsSignedData {@link CMSSignedData}
	 * @return cmsSignedData.getSignedContentTypeOID() as DER encoded
	 */
	private byte[] getEncodedContentType(final CMSSignedData cmsSignedData) {
		final ContentInfo contentInfo = cmsSignedData.toASN1Structure();
		final SignedData signedData = SignedData.getInstance(contentInfo.getContent());
		return DSSASN1Utils.getDEREncoded(signedData.getEncapContentInfo().getContentType());
	}

	/**
	 * 3) Fields version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, and
	 * signature within the SignedData.signerInfos’s item corresponding to the signature being archive
	 * time-stamped, in their order of appearance.
	 *
	 * @param signerInformation {@link SignerInformation}
	 * @param digestCalculator {@link DSSMessageDigestCalculator} to populate
	 */
	private void writeSignedFields(final SignerInformation signerInformation, final DSSMessageDigestCalculator digestCalculator) {
		byte[] bytes = null;
		final SignerInfo signerInfo = signerInformation.toASN1Structure();

		final ASN1Integer version = signerInfo.getVersion();
		bytes = DSSASN1Utils.getDEREncoded(version);
		digestCalculator.update(bytes);
		if (LOG.isDebugEnabled()) {
			LOG.debug("getSignedFields Version={}", Utils.toBase64(bytes));
		}

		final SignerIdentifier sid = signerInfo.getSID();
		bytes = DSSASN1Utils.getDEREncoded(sid);
		digestCalculator.update(bytes);
		if (LOG.isDebugEnabled()) {
			LOG.debug("getSignedFields Sid={}", Utils.toBase64(bytes));
		}

		final AlgorithmIdentifier digestAlgorithm = signerInfo.getDigestAlgorithm();
		bytes = DSSASN1Utils.getDEREncoded(digestAlgorithm);
		digestCalculator.update(bytes);
		if (LOG.isDebugEnabled()) {
			LOG.debug("getSignedFields DigestAlgorithm={}", Utils.toBase64(bytes));
		}

		final DERTaggedObject signedAttributes = CMSUtils.getDERSignedAttributes(signerInformation);
		bytes = DSSASN1Utils.getDEREncoded(signedAttributes);
		digestCalculator.update(bytes);
		if (LOG.isDebugEnabled()) {
			LOG.debug("getSignedFields SignedAttributes={}", Utils.toBase64(bytes));
		}

		final AlgorithmIdentifier digestEncryptionAlgorithm = signerInfo.getDigestEncryptionAlgorithm();
		bytes = DSSASN1Utils.getDEREncoded(digestEncryptionAlgorithm);
		digestCalculator.update(bytes);
		if (LOG.isDebugEnabled()) {
			LOG.debug("getSignedFields DigestEncryptionAlgorithm={}", Utils.toBase64(bytes));
		}

		final ASN1OctetString encryptedDigest = signerInfo.getEncryptedDigest();
		bytes = DSSASN1Utils.getDEREncoded(encryptedDigest);
		digestCalculator.update(bytes);
		if (LOG.isDebugEnabled()) {
			LOG.debug("getSignedFields EncryptedDigest={}", Utils.toBase64(bytes));
		}
	}

}
