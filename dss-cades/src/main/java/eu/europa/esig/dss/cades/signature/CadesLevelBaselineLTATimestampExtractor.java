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

import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.ArchiveTimestampHashIndexVersion;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.tsp.ArchiveTimestampHashIndexStatus;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
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
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

import static eu.europa.esig.dss.spi.OID.id_aa_ATSHashIndexV2;
import static eu.europa.esig.dss.spi.OID.id_aa_ATSHashIndexV3;

/**
 * Extracts the necessary information to compute the CAdES Archive Timestamp V3.
 * <p>
 * See "5.5.2 The ats-hash-index-v3 attribute":
 * <p>
 * The ats-hash-index-v3 is invalid if it contains a reference for which the original value is not found, i.e.:
 * - a reference represented by an entry in certificatesHashIndex which corresponds to no instance of
 *   CertificateChoices within certificates field of the root SignedData;
 * - a reference represented by an entry in crlsHashIndex which corresponds to no instance of
 *   RevocationInfoChoice within crls field of the root SignedData; or
 * - a reference represented by an entry in unsignedAttrValuesHashIndex which corresponds to no octet
 *   stream resulting from concatenating one of the AttributeValue instances within field
 *   Attribute.attrValues and the corresponding Attribute.attrType within one Attribute
 *   instance in unsignedAttrs field of the SignerInfo.
 *
 */
public class CadesLevelBaselineLTATimestampExtractor {

	private static final Logger LOG = LoggerFactory.getLogger(CadesLevelBaselineLTATimestampExtractor.class);

	/** CAdESSignature */
	private final CAdESSignature signature;

	/**
	 * This is the default constructor for the {@code CadesLevelBaselineLTATimestampExtractor}.
	 *
	 * @param cadesSignature
	 *            {@code CAdESSignature} related to the archive timestamp
	 */
	public CadesLevelBaselineLTATimestampExtractor(final CAdESSignature cadesSignature) {
		Objects.requireNonNull(cadesSignature, "CAdESSignature cannot be null!");
		this.signature = cadesSignature;
	}

	/**
	 * The ats-hash-index unsigned attribute provides an unambiguous imprint of the essential components of a CAdES
	 * signature for use in the archive time-stamp (see 6.4.3). These essential components are elements of the following
	 * ASN.1
	 * SET OF structures: unsignedAttrs, SignedData.certificates, and SignedData.crls.
	 * <p>
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
		final AlgorithmIdentifier algorithmIdentifier = getHashIndexDigestAlgorithmIdentifier(hashIndexDigestAlgorithm);
		final ASN1Sequence certificatesHashIndex = getCertificatesHashIndex(hashIndexDigestAlgorithm);
		final ASN1Sequence crLsHashIndex = getCRLsHashIndex(hashIndexDigestAlgorithm);
		final ASN1Sequence unsignedAttributesHashIndex = getUnsignedAttributesHashIndex(
				signerInformation, atsHashIndexVersionIdentifier, hashIndexDigestAlgorithm);
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
		ASN1ObjectIdentifier atsHashIndexVersionIdentifier = CMSUtils.getAtsHashIndexVersionIdentifier(unsignedAttributes);
		ASN1Sequence atsHashIndex = CMSUtils.getAtsHashIndexByVersion(unsignedAttributes, atsHashIndexVersionIdentifier);
		if (atsHashIndex == null) {
			LOG.warn("A valid atsHashIndex [oid: {}] has not been found for a timestamp with id {}",
					atsHashIndexVersionIdentifier, timestampToken.getDSSIdAsString());
		}
		final ArchiveTimestampHashIndexStatus atsHashIndexStatus = buildArchiveTimestampHashIndexStatus(atsHashIndexVersionIdentifier);
		final AlgorithmIdentifier derObjectAlgorithmIdentifier = getAlgorithmIdentifier(atsHashIndex);
		final DigestAlgorithm hashIndexDigestAlgorithm = getHashIndexDigestAlgorithm(derObjectAlgorithmIdentifier);
		final ASN1Sequence certificatesHashIndex = getVerifiedCertificatesHashIndex(atsHashIndex, hashIndexDigestAlgorithm, atsHashIndexStatus);
		final ASN1Sequence crLsHashIndex = getVerifiedCRLsHashIndex(atsHashIndex, hashIndexDigestAlgorithm, atsHashIndexStatus);
		final ASN1Sequence verifiedAttributesHashIndex = getVerifiedUnsignedAttributesHashIndex(
				signerInformation, atsHashIndex, atsHashIndexVersionIdentifier, hashIndexDigestAlgorithm, atsHashIndexStatus);
		timestampToken.setAtsHashIndexStatus(atsHashIndexStatus);
		return getComposedAtsHashIndex(derObjectAlgorithmIdentifier, certificatesHashIndex, crLsHashIndex, 
				verifiedAttributesHashIndex, atsHashIndexVersionIdentifier);
	}

	private ArchiveTimestampHashIndexStatus buildArchiveTimestampHashIndexStatus(ASN1ObjectIdentifier atsHashIndexVersionIdentifier) {
		ArchiveTimestampHashIndexStatus status = new ArchiveTimestampHashIndexStatus();
		ArchiveTimestampHashIndexVersion version = null;
		if (atsHashIndexVersionIdentifier != null) {
			version = ArchiveTimestampHashIndexVersion.forOid(atsHashIndexVersionIdentifier.getId());
		}
		if (version != null) {
			status.setVersion(version);
		} else {
			status.addErrorMessage("The ats-hash-index was not found or not supported.");
		}
		return status;
	}

	/**
	 * The field hashIndAlgorithm contains an identifier of the hash algorithm used to compute the hash values
	 * contained in certificatesHashIndex, crlsHashIndex, and unsignedAttrsHashIndex. This algorithm
	 * shall be the same as the hash algorithm used for computing the archive time-stamp’s message imprint.
	 * <p>
	 * hashIndAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256}
	 *
	 * @param algorithmIdentifier {@link AlgorithmIdentifier} extracted from the ats-hash-table-v3
	 * @return {@link DigestAlgorithm}
	 */
	private DigestAlgorithm getHashIndexDigestAlgorithm(AlgorithmIdentifier algorithmIdentifier) {
		return algorithmIdentifier != null ? DigestAlgorithm.forOID(algorithmIdentifier.getAlgorithm().getId()) :
				CMSUtils.DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO;
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
	 * @param hashIndexDigestAlgorithm {@link DigestAlgorithm}
	 * @return {@link ASN1Sequence}
	 */
	private ASN1Sequence getCertificatesHashIndex(DigestAlgorithm hashIndexDigestAlgorithm) {

		final ASN1EncodableVector certificatesHashIndexVector = new ASN1EncodableVector();

		List<CertificateToken> signedDataCertificates = signature.getCertificateSource().getSignedDataCertificates();
		for (final CertificateToken certificateToken : signedDataCertificates) {
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
	 * @param timestampHashIndex {@link Attribute}
	 * @param hashIndexDigestAlgorithm {@link DigestAlgorithm}
	 * @param atsHashIndexStatus {@link ArchiveTimestampHashIndexStatus} contains information about the ats-hash-index validation
	 * @return {@link ASN1Sequence}
	 */
	private ASN1Sequence getVerifiedCertificatesHashIndex(final ASN1Sequence timestampHashIndex,
			DigestAlgorithm hashIndexDigestAlgorithm, ArchiveTimestampHashIndexStatus atsHashIndexStatus) {

		final ASN1Sequence certHashes = CMSUtils.getCertificatesHashIndex(timestampHashIndex);
		final List<DEROctetString> certHashesList = DSSASN1Utils.getDEROctetStrings(certHashes);

		// Evaluate CMSSignedData.certificates
		List<CertificateToken> signedDataCertificates = signature.getCertificateSource().getSignedDataCertificates();
		for (final CertificateToken certificateToken : signedDataCertificates) {
			final byte[] digest = certificateToken.getDigest(hashIndexDigestAlgorithm);
			final DEROctetString derOctetStringDigest = new DEROctetString(digest);
			if (certHashesList.remove(derOctetStringDigest)) {
				// attribute present in CMSSignedData.certificates and in timestamp's hash-table
				LOG.debug("Cert {} present in timestamp", certificateToken.getAbbreviation());
			} else {
				LOG.debug("Cert {} not present in timestamp", certificateToken.getAbbreviation());
			}
		}
		// Evaluate against other certificate entries (lax processing)
		if (!certHashesList.isEmpty()) {
			List<CertificateToken> allCertificates = signature.getCompleteCertificateSource().getCertificates();
			for (final CertificateToken certificateToken : allCertificates) {
				final byte[] digest = certificateToken.getDigest(hashIndexDigestAlgorithm);
				final DEROctetString derOctetStringDigest = new DEROctetString(digest);
				if (certHashesList.remove(derOctetStringDigest)) {
					LOG.warn("ats-hash-index attribute contains certificate '{}' present outside CMSSignedData.certificates", certificateToken.getAbbreviation());
				}
			}

			if (certHashesList.isEmpty()) {
				atsHashIndexStatus.addErrorMessage(
						"ats-hash-index attribute contains certificates present outside of CMSSignedData.certificates.");
			} else {
				LOG.warn("{} attribute(s) hash in Cert Hashes has not been found in document attributes: {}", certHashesList.size(), certHashesList);
				atsHashIndexStatus.addErrorMessage(
						"Some ats-hash-index attribute certificates have not been found in document attributes.");
			}
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
	 * @param hashIndexDigestAlgorithm {@link DigestAlgorithm}
	 * @return {@link ASN1Sequence}
	 */
	@SuppressWarnings("unchecked")
	private ASN1Sequence getCRLsHashIndex(DigestAlgorithm hashIndexDigestAlgorithm) {
		final ASN1EncodableVector crlsHashIndex = new ASN1EncodableVector();

		final SignedData signedData = SignedData.getInstance(signature.getCmsSignedData().toASN1Structure().getContent());
		final ASN1Set signedDataCRLs = signedData.getCRLs();
		if (signedDataCRLs != null) {
			final Enumeration<ASN1Encodable> crLs = signedDataCRLs.getObjects();
			if (crLs != null) {
				while (crLs.hasMoreElements()) {
					final ASN1Encodable asn1Encodable = crLs.nextElement();
					digestAndAddToList(crlsHashIndex, DSSASN1Utils.getDEREncoded(asn1Encodable), hashIndexDigestAlgorithm);
				}
			}
		}

		return new DERSequence(crlsHashIndex);
	}

	private void digestAndAddToList(ASN1EncodableVector crlsHashIndex, byte[] encoded, DigestAlgorithm hashIndexDigestAlgorithm) {
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
	 * @param timestampHashIndex {@link ASN1Sequence}
	 * @param hashIndexDigestAlgorithm {@link DigestAlgorithm}
	 * @param atsHashIndexStatus {@link ArchiveTimestampHashIndexStatus}
	 * @return {@link ASN1Sequence}
	 */
	@SuppressWarnings("unchecked")
	private ASN1Sequence getVerifiedCRLsHashIndex(final ASN1Sequence timestampHashIndex, DigestAlgorithm hashIndexDigestAlgorithm,
												  ArchiveTimestampHashIndexStatus atsHashIndexStatus) {
		final ASN1Sequence crlHashes = CMSUtils.getCRLHashIndex(timestampHashIndex);
		final List<DEROctetString> crlHashesList = DSSASN1Utils.getDEROctetStrings(crlHashes);

		final SignedData signedData = SignedData.getInstance(signature.getCmsSignedData().toASN1Structure().getContent());
		final ASN1Set signedDataCRLs = signedData.getCRLs();
		if (signedDataCRLs != null) {
			final Enumeration<ASN1Encodable> crLs = signedDataCRLs.getObjects();
			if (crLs != null) {
				while (crLs.hasMoreElements()) {
					final ASN1Encodable asn1Encodable = crLs.nextElement();
					handleRevocationEncoded(crlHashesList, DSSASN1Utils.getDEREncoded(asn1Encodable), hashIndexDigestAlgorithm);
				}
			}
		}

		// Evaluate against other certificate entries (lax processing)
		if (!crlHashesList.isEmpty()) {

			List<EncapsulatedRevocationTokenIdentifier<CRL>> crlBinaries = signature.getCompleteCRLSource().getAllRevocationBinaries();
			for (EncapsulatedRevocationTokenIdentifier<CRL> crl : crlBinaries) {
				final byte[] digest = crl.getDigestValue(hashIndexDigestAlgorithm);
				final DEROctetString derOctetStringDigest = new DEROctetString(digest);
				if (crlHashesList.remove(derOctetStringDigest)) {
					LOG.warn("ats-hash-index attribute contains CRL '{}' present outside CMSSignedData.crls", crl.getDSSId().asXmlId());
				}
			}

			List<EncapsulatedRevocationTokenIdentifier<OCSP>> ocspBinaries = signature.getCompleteOCSPSource().getAllRevocationBinaries();
			for (EncapsulatedRevocationTokenIdentifier<OCSP> ocsp : ocspBinaries) {
				OCSPResponseBinary binary = (OCSPResponseBinary) ocsp;
				ASN1ObjectIdentifier objectIdentifier = binary.getAsn1ObjectIdentifier();
				if (objectIdentifier != null) {
					// OCSPObjectIdentifiers.id_pkix_ocsp_basic or OCSPObjectIdentifiers.id_ri_ocsp_response cases
					DEROctetString derOctetStringDigest = getOcspResponseDigest(
							binary.getBasicOCSPRespContent(), objectIdentifier, hashIndexDigestAlgorithm);
					if (crlHashesList.remove(derOctetStringDigest)) {
						LOG.warn("ats-hash-index attribute contains OCSP '{}' present outside CMSSignedData.crls", ocsp.getDSSId().asXmlId());
					}
				} else {
					// CMSObjectIdentifiers.id_ri_ocsp_response full binaries
					objectIdentifier = OCSPObjectIdentifiers.id_pkix_ocsp_response;
					DEROctetString derOctetStringDigest = getOcspResponseDigest(
							binary.getBinaries(), objectIdentifier, hashIndexDigestAlgorithm);
					if (crlHashesList.remove(derOctetStringDigest)) {
						LOG.warn("ats-hash-index attribute contains OCSP '{}' present outside CMSSignedData.crls", ocsp.getDSSId().asXmlId());
					}
				}
			}

			if (crlHashesList.isEmpty()) {
				atsHashIndexStatus.addErrorMessage(
						"ats-hash-index attribute contains crls present outside of CMSSignedData.crls.");
			} else {
				LOG.warn("{} attribute(s) hash in CRL Hashes has not been found in SignedData.crls: {}", crlHashesList.size(), crlHashesList);
				atsHashIndexStatus.addErrorMessage(
						"Some ats-hash-index attribute crls have not been found in document attributes.");
			}

		}

		return crlHashes;
	}

	private DEROctetString getOcspResponseDigest(byte[] binaries, ASN1ObjectIdentifier objectIdentifier,
												 DigestAlgorithm digestAlgorithm) {
		byte[] encoded = CMSUtils.getSignedDataEncodedOCSPResponse(binaries, objectIdentifier);
		byte[] digest = DSSUtils.digest(digestAlgorithm, encoded);
		return new DEROctetString(digest);
	}

	private void handleRevocationEncoded(List<DEROctetString> crlHashesList, byte[] revocationEncoded, DigestAlgorithm hashIndexDigestAlgorithm) {

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
	 * @param hashIndexDigestAlgorithm {@link DigestAlgorithm}
	 * @return {@link ASN1Sequence}
	 */
	private ASN1Sequence getUnsignedAttributesHashIndex(SignerInformation signerInformation,
			ASN1ObjectIdentifier atsHashIndexVersionIdentifier, DigestAlgorithm hashIndexDigestAlgorithm) {

		final ASN1EncodableVector unsignedAttributesHashIndex = new ASN1EncodableVector();
		AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
		final ASN1EncodableVector asn1EncodableVector = unsignedAttributes.toASN1EncodableVector();
		for (int i = 0; i < asn1EncodableVector.size(); i++) {
			final Attribute attribute = (Attribute) asn1EncodableVector.get(i);
			List<DEROctetString> attributeDerOctetStringHashes = getAttributeDerOctetStringHashes(
					attribute, atsHashIndexVersionIdentifier, hashIndexDigestAlgorithm);
			for (DEROctetString derOctetStringDigest : attributeDerOctetStringHashes) {
				unsignedAttributesHashIndex.add(derOctetStringDigest);
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
	 * <p>
	 * We check that every hash attribute found in the timestamp token is found if
	 * the signerInformation.
	 * <p>
	 * If there is more unsigned attributes in the signerInformation than present in
	 * the hash attributes list (and there is at least the
	 * archiveTimestampAttributeV3), we don't report any error nor which attributes
	 * are signed by the timestamp. If there is some attributes that are not present
	 * or altered in the signerInformation, we just return some empty sequence to
	 * make sure that the timestamped data will not match. We do not report which
	 * attributes hash are present if any.
	 * <p>
	 * If there is not attribute at all in the archive timestamp hash index, that
	 * would means we didn't check anything.
	 *
	 * @param signerInformation  {@link SignerInformation}
	 * @param timestampHashIndex {@link ASN1Sequence}
	 * @param atsHashIndexVersionIdentifier {@link ASN1ObjectIdentifier}
	 * @param hashIndexDigestAlgorithm {@link DigestAlgorithm}
	 * @return {@link ASN1Sequence} unsignedAttributesHashes
	 */
	private ASN1Sequence getVerifiedUnsignedAttributesHashIndex(SignerInformation signerInformation,
			ASN1Sequence timestampHashIndex, ASN1ObjectIdentifier atsHashIndexVersionIdentifier,
			DigestAlgorithm hashIndexDigestAlgorithm, ArchiveTimestampHashIndexStatus atsHashIndexStatus) {
		
		final ASN1Sequence unsignedAttributesHashes = CMSUtils.getUnsignedAttributesHashIndex(timestampHashIndex);
		final List<DEROctetString> timestampUnsignedAttributesHashesList = DSSASN1Utils.getDEROctetStrings(unsignedAttributesHashes);
		
		AttributeTable unsignedAttributes = CMSUtils.getUnsignedAttributes(signerInformation);
		final ASN1EncodableVector asn1EncodableVector = unsignedAttributes.toASN1EncodableVector();
		for (int i = 0; i < asn1EncodableVector.size(); i++) {
			final Attribute attribute = (Attribute) asn1EncodableVector.get(i);
			List<DEROctetString> attributeDerOctetStringHashes = getAttributeDerOctetStringHashes(
					attribute, atsHashIndexVersionIdentifier, hashIndexDigestAlgorithm);
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
			LOG.warn("{} attribute(s) hash in Timestamp has not been found in unsignedAttrs: {}", timestampUnsignedAttributesHashesList.size(),
					timestampUnsignedAttributesHashesList);
			atsHashIndexStatus.addErrorMessage(
					"Some ats-hash-index attribute entries have not been found in unsignedAttrs.");
		}
		// return the original DERSequence
		return unsignedAttributesHashes;
	}

	private List<DEROctetString> getAttributeDerOctetStringHashes(Attribute attribute, ASN1ObjectIdentifier atsHashIndexVersionIdentifier,
																  DigestAlgorithm hashIndexDigestAlgorithm) {
		List<byte[]> octets = CMSUtils.getOctetStringForAtsHashIndex(attribute, atsHashIndexVersionIdentifier);
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
		return DSSASN1Utils.getAlgorithmIdentifier(atsHashIndexValue);
	}

	private AlgorithmIdentifier getHashIndexDigestAlgorithmIdentifier(DigestAlgorithm hashIndexDigestAlgorithm) {
		// If the algorithm identifier in ATSHashIndex has the default value, then it can be omitted
		if (hashIndexDigestAlgorithm.getOid().equals(CMSUtils.DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO.getOid())) {
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
		 * binary encoded form without any modification and including the tag, length and value octets:
		 */
		final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
		byte[] bytes = null;
		if (LOG.isDebugEnabled()) {
			LOG.debug("Archive Timestamp Data v3 is:");
		}

		bytes = getEncodedContentType(signature.getCmsSignedData()); // OID
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
		return DSSASN1Utils.getDEREncoded(CMSUtils.getEncapsulatedContentType(cmsSignedData));
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
