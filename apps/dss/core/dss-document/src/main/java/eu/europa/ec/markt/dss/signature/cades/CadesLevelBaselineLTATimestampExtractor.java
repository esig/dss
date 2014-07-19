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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
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
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.OID;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;

/**
 * Extracts the necessary information to compute the CAdES Archive Timestamp V3.
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class CadesLevelBaselineLTATimestampExtractor {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(CadesLevelBaselineLTATimestampExtractor.class);
    public static final DigestAlgorithm DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO = DigestAlgorithm.SHA256;
    /**
     * If the algorithm identifier in ATSHashIndex as the default value (DEFAULT_ARCHIVE_TIMESTAMP_HASH_ALGO), it can be omited.
     */
    private static final boolean OMIT_ALGORITHM_IDENTIFIER_IF_DEFAULT = true;

    /**
     * The field hashIndAlgorithm contains an identifier of the hash algorithm used to compute the hash values
     * contained in certificatesHashIndex, crlsHashIndex, and unsignedAttrsHashIndex. This algorithm
     * shall be the same as the hash algorithm used for computing the archive time-stamp’s message imprint.
     * <p/>
     * hashIndAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
     */
    private DigestAlgorithm hashIndexDigestAlgorithm;

    private final Set<DERObjectIdentifier> excludedAttributesFromAtsHashIndex = new HashSet<DERObjectIdentifier>();

    public CadesLevelBaselineLTATimestampExtractor() {
        /* these attribute are validated elsewhere */
        excludedAttributesFromAtsHashIndex.add(PKCSObjectIdentifiers.id_aa_ets_certValues);
        excludedAttributesFromAtsHashIndex.add(PKCSObjectIdentifiers.id_aa_ets_revocationValues);
    }

    /**
     * The ats-hash-index unsigned attribute provides an unambiguous imprint of the essential components of a CAdES
     * signature for use in the archive time-stamp (see 6.4.3). These essential components are elements of the following ASN.1
     * SET OF structures: unsignedAttrs, SignedData.certificates, and SignedData.crls.
     * <p/>
     * The ats-hash-index attribute value has the ASN.1 syntax ATSHashIndex:
     * ATSHashIndex ::= SEQUENCE {
     * hashIndAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
     * certificatesHashIndex SEQUENCE OF OCTET STRING,
     * crlsHashIndex SEQUENCE OF OCTET STRING,
     *
     * @param signerInformation
     * @param cAdESSignature
     * @return
     */
    public Attribute getAtsHashIndex(SignerInformation signerInformation, DigestAlgorithm hashIndexDigestAlgorithm, CAdESSignature cAdESSignature) throws DSSException {

        this.hashIndexDigestAlgorithm = hashIndexDigestAlgorithm;
        final AlgorithmIdentifier algorithmIdentifier = getHashIndexDigestAlgorithmIdentifier();
        final ASN1Sequence certificatesHashIndex = getCertificatesHashIndex(cAdESSignature);
        final ASN1Sequence crLsHashIndex = getCRLsHashIndex(cAdESSignature);
        final ASN1Sequence unsignedAttributesHashIndex = getUnsignedAttributesHashIndex(signerInformation);
        return getComposedAtsHashIndex(algorithmIdentifier, certificatesHashIndex, crLsHashIndex, unsignedAttributesHashIndex);

    }

    /**
     * get the atsHash index for verification of the provided token.
     *
     * @param signerInformation
     * @param cAdESSignature
     * @param timestampToken    @return
     */
    public Attribute getVerifiedAtsHashIndex(SignerInformation signerInformation, CAdESSignature cAdESSignature, TimestampToken timestampToken) throws DSSException {

        final AlgorithmIdentifier derObjectAlgorithmIdentifier = getAlgorithmIdentifier(timestampToken);
        final ASN1Sequence certificatesHashIndex = getVerifiedCertificatesHashIndex(cAdESSignature, timestampToken);
        final ASN1Sequence crLsHashIndex = getVerifiedCRLsHashIndex(cAdESSignature, timestampToken);
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
        return new Attribute(OID.id_aa_ATSHashIndex, new DERSet(derSequence));
    }

    /**
     * The field certificatesHashIndex is a sequence of octet strings. Each one contains the hash value of one
     * instance of CertificateChoices within certificates field of the root SignedData. A hash value for
     * every instance of CertificateChoices, as present at the time when the corresponding archive time-stamp is
     * requested, shall be included in certificatesHashIndex. No other hash value shall be included in this field.
     *
     * @param cAdESSignature
     * @return
     * @throws eu.europa.ec.markt.dss.exception.DSSException
     */
    private ASN1Sequence getCertificatesHashIndex(CAdESSignature cAdESSignature) throws DSSException {

        final ASN1EncodableVector certificatesHashIndexVector = new ASN1EncodableVector();

        final List<CertificateToken> certificateTokens = cAdESSignature.getCertificatesWithinSignatureAndTimestamps();
        for (final CertificateToken certificateToken : certificateTokens) {
            final byte[] encodedCertificate = certificateToken.getEncoded();
            final byte[] digest = DSSUtils.digest(hashIndexDigestAlgorithm, encodedCertificate);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Adding to CertificatesHashIndex DSS-Identifier: {} with hash {}", certificateToken.getDSSId(), DSSUtils.encodeHexString(digest));
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
     * @param cAdESSignature
     * @return
     * @throws eu.europa.ec.markt.dss.exception.DSSException
     */
    @SuppressWarnings("unchecked")
    private ASN1Sequence getVerifiedCertificatesHashIndex(CAdESSignature cAdESSignature, TimestampToken timestampToken) throws DSSException {

        final ASN1Sequence certHashes = getCertificatesHashIndex(timestampToken);
        final ArrayList<DEROctetString> certHashesList = Collections.list(certHashes.getObjects());

        final List<CertificateToken> certificates = cAdESSignature.getCertificatesWithinSignatureAndTimestamps();
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
     * @param cAdESSignature
     * @return
     * @throws eu.europa.ec.markt.dss.exception.DSSException
     */
    @SuppressWarnings("unchecked")
    private ASN1Sequence getCRLsHashIndex(CAdESSignature cAdESSignature) throws DSSException {

        final ASN1EncodableVector crlsHashIndex = new ASN1EncodableVector();

        final SignedData signedData = SignedData.getInstance(cAdESSignature.getCmsSignedData().toASN1Structure().getContent());
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
            LOG.debug("Adding to crlsHashIndex with hash {}", DSSUtils.encodeHexString(digest));
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
     * @param cAdESSignature
     * @return
     * @throws eu.europa.ec.markt.dss.exception.DSSException
     */
    @SuppressWarnings("unchecked")
    private ASN1Sequence getVerifiedCRLsHashIndex(CAdESSignature cAdESSignature, TimestampToken timestampToken) throws DSSException {

        final ASN1Sequence crlHashes = getCRLHashIndex(timestampToken);
        final ArrayList<DEROctetString> crlHashesList = Collections.list(crlHashes.getObjects());

        final SignedData signedData = SignedData.getInstance(cAdESSignature.getCmsSignedData().toASN1Structure().getContent());
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
     * <p/>
     * We check that every hash attribute found in the timestamp token is found if the signerInformation.
     * <p/>
     * If there is more unsigned attributes in the signerInformation than present in the hash attributes list
     * (and there is at least the archiveTimestampAttributeV3), we don't report any error nor which attributes are signed by the timestamp.
     * If there is some attributes that are not present or altered in the signerInformation, we just return some empty sequence to make
     * sure that the timestamped data will not match. We do not report which attributes hash are present if any.
     * <p/>
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
            final DERObjectIdentifier attrType = attribute.getAttrType();
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
        int UNSIGNED_ATTRIBUTES_INDEX = 2;
        if (timestampAttributeAtsHashIndexValue.size() > 3) {
            UNSIGNED_ATTRIBUTES_INDEX++;
        }
        return (ASN1Sequence) timestampAttributeAtsHashIndexValue.getObjectAt(UNSIGNED_ATTRIBUTES_INDEX).toASN1Primitive();
    }

    /**
     * Extract the Unsigned Attribute Archive Timestamp Crl Hash Index from a timestampToken
     *
     * @param timestampToken
     * @return
     */
    private ASN1Sequence getCRLHashIndex(TimestampToken timestampToken) {
        final ASN1Sequence timestampAttributeAtsHashIndexValue = getAtsHashIndex(timestampToken);
        int CRL_INDEX = 1;
        if (timestampAttributeAtsHashIndexValue.size() > 3) {
            CRL_INDEX++;
        }
        return (ASN1Sequence) timestampAttributeAtsHashIndexValue.getObjectAt(CRL_INDEX).toASN1Primitive();
    }

    /**
     * Extract the Unsigned Attribute Archive Timestamp Cert Hash Index from a timestampToken
     *
     * @param timestampToken
     * @return
     */
    private ASN1Sequence getCertificatesHashIndex(TimestampToken timestampToken) {
        final ASN1Sequence timestampAttributeAtsHashIndexValue = getAtsHashIndex(timestampToken);
        int CERT_INDEX = 0;
        if (timestampAttributeAtsHashIndexValue.size() > 3) {
            CERT_INDEX++;
        }
        return (ASN1Sequence) timestampAttributeAtsHashIndexValue.getObjectAt(CERT_INDEX).toASN1Primitive();
    }

    /**
     * Extract the Unsigned Attribute Archive Timestamp Cert Hash Index from a timestampToken
     *
     * @param timestampToken
     * @return
     */
    private AlgorithmIdentifier getAlgorithmIdentifier(TimestampToken timestampToken) {
        final ASN1Sequence timestampAttributeAtsHashIndexValue = getAtsHashIndex(timestampToken);
        if (timestampAttributeAtsHashIndexValue.size() > 3) {
            final int ALGO_INDEX = 0;
            final ASN1Encodable derEncodable = timestampAttributeAtsHashIndexValue.getObjectAt(ALGO_INDEX);
            if (derEncodable instanceof ASN1Sequence) {
                final ASN1Sequence derSequence = (ASN1Sequence) derEncodable;
                hashIndexDigestAlgorithm = DigestAlgorithm.forOID(((DERObjectIdentifier) derSequence.getObjectAt(0)).getId());
                return AlgorithmIdentifier.getInstance(derSequence);
            } else if (derEncodable instanceof DERObjectIdentifier) {
                ASN1ObjectIdentifier derObjectIdentifier = ASN1ObjectIdentifier.getInstance(derEncodable);
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
        final Attribute atsHashIndexAttribute = timestampTokenUnsignedAttributes.get(OID.id_aa_ATSHashIndex);
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

    public byte[] getArchiveTimestampDataV3(CAdESSignature cadesSignature, SignerInformation signerInformation, Attribute atsHashIndexAttribute, byte[] originalDocument,
                                            DigestAlgorithm digestAlgorithm) throws DSSException {
        final CMSSignedData cmsSignedData = cadesSignature.getCmsSignedData();
        final byte[] encodedContentType = getEncodedContentType(cmsSignedData);
        final byte[] signedDataDigest = DSSUtils.digest(digestAlgorithm, originalDocument);
        final byte[] encodedFields = geSignedFields(signerInformation);
        final byte[] encodedAtsHashIndex = DSSASN1Utils.getDEREncoded(atsHashIndexAttribute.getAttrValues().getObjectAt(0));
        final byte[] dataToTimestamp = concatenateArrays(encodedContentType, signedDataDigest, encodedFields, encodedAtsHashIndex);
        if (LOG.isDebugEnabled()) {
            LOG.debug("eContentType={}", DSSUtils.encodeHexString(encodedContentType));
            LOG.debug("signedDataDigest={}", DSSUtils.encodeHexString(signedDataDigest));
            LOG.debug("encodedFields={}", DSSUtils.encodeHexString(encodedFields));
            LOG.debug("encodedAtsHashIndex={}", DSSUtils.encodeHexString(encodedAtsHashIndex));
            LOG.debug("Archive Timestamp Data v3 is: {}", DSSUtils.encodeHexString(dataToTimestamp));
        }
        return dataToTimestamp;
    }

    /**
     * The input for the archive-time-stamp-v3’s message imprint computation shall be the concatenation (in the
     * order shown by the list below) of the signed data hash (see bullet 2 below) and certain fields in their binary encoded
     * form without any modification and including the tag, length and value octets:
     *
     * @param byteArrays
     * @return
     * @throws eu.europa.ec.markt.dss.exception.DSSException
     */
    private byte[] concatenateArrays(byte[]... byteArrays) throws DSSException {
        try {
            ByteArrayOutputStream concatenationResult = new ByteArrayOutputStream();
            for (final byte[] byteArray : byteArrays) {
                concatenationResult.write(byteArray);
            }
            return concatenationResult.toByteArray();
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    /**
     * 1) The SignedData.encapContentInfo.eContentType.
     *
     * @param cmsSignedData
     * @return
     */
    private byte[] getEncodedContentType(CMSSignedData cmsSignedData) {
        ContentInfo contentInfo = cmsSignedData.toASN1Structure();
        SignedData signedData = SignedData.getInstance(contentInfo.getContent());
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
    private byte[] geSignedFields(SignerInformation signerInformation) {
        final SignerInfo signerInfo = signerInformation.toASN1Structure();
        final ASN1Integer version = signerInfo.getVersion();
        final SignerIdentifier sid = signerInfo.getSID();
        final AlgorithmIdentifier digestAlgorithm = signerInfo.getDigestAlgorithm();
        final ASN1TaggedObject signedAttributes = new DERTaggedObject(false, 0, new DERSequence(signerInfo.getAuthenticatedAttributes().toArray()));
        final AlgorithmIdentifier digestEncryptionAlgorithm = signerInfo.getDigestEncryptionAlgorithm();
        final ASN1OctetString encryptedDigest = signerInfo.getEncryptedDigest();

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            final byte[] derEncodedVersion = DSSASN1Utils.getDEREncoded(version);
            final byte[] derEncodedSid = DSSASN1Utils.getDEREncoded(sid);
            final byte[] derEncodedDigestAlgo = DSSASN1Utils.getDEREncoded(digestAlgorithm);
            final byte[] derEncodedSignedAttributes = DSSASN1Utils.getDEREncoded(signedAttributes);
            final byte[] derEncodedDigestEncryptionAlgo = DSSASN1Utils.getDEREncoded(digestEncryptionAlgorithm);
            final byte[] derEncodedEncryptedDigest = DSSASN1Utils.getDEREncoded(encryptedDigest);
            if (LOG.isDebugEnabled()) {
                LOG.debug("getSignedFields Version={}", DSSUtils.encodeHexString(derEncodedVersion));
                LOG.debug("getSignedFields Sid={}", DSSUtils.encodeHexString(derEncodedSid));
                LOG.debug("getSignedFields DigestAlgo={}", DSSUtils.encodeHexString(derEncodedDigestAlgo));
                LOG.debug("getSignedFields SignedAttributes={}", DSSUtils.encodeHexString(derEncodedSignedAttributes)); // bad
                LOG.debug("getSignedFields DigestEncryptionAlgo={}", DSSUtils.encodeHexString(derEncodedDigestEncryptionAlgo));
                LOG.debug("getSignedFields EncryptedDigest={}", DSSUtils.encodeHexString(derEncodedEncryptedDigest));
            }
            byteArrayOutputStream.write(derEncodedVersion);
            byteArrayOutputStream.write(derEncodedSid);
            byteArrayOutputStream.write(derEncodedDigestAlgo);
            byteArrayOutputStream.write(derEncodedSignedAttributes);
            byteArrayOutputStream.write(derEncodedDigestEncryptionAlgo);
            byteArrayOutputStream.write(derEncodedEncryptedDigest);
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }
}
