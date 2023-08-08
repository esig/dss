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
package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.tsp.TimestampSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampTokenComparator;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.revocation.ListRevocationSource;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.validation.SignatureAttribute;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignatureProperties;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.validation.scope.EncapsulatedTimestampScopeFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * The timestamp source of a signature
 *
 * @param <AS> {@code AdvancedSignature} implementation
 * @param <SA> the corresponding {@code SignatureAttribute}
 */
public abstract class SignatureTimestampSource<AS extends AdvancedSignature, SA extends SignatureAttribute>
        extends AbstractTimestampSource implements TimestampSource {

    private static final long serialVersionUID = -6099954395130813702L;

    private static final Logger LOG = LoggerFactory.getLogger(SignatureTimestampSource.class);

    /**
     * The signature is being validated
     */
    protected final AS signature;

    /**
     * CRL revocation source containing merged data from signature and timestamps
     */
    protected ListRevocationSource<CRL> crlSource;

    /**
     * OCSP revocation source containing merged data from signature and timestamps
     */
    protected ListRevocationSource<OCSP> ocspSource;

    /**
     * CertificateSource containing merged data from signature and timestamps
     */
    protected ListCertificateSource certificateSource;

    /**
     * Enclosed content timestamps.
     */
    protected transient List<TimestampToken> contentTimestamps;

    /**
     * Enclosed signature timestamps.
     */
    protected transient List<TimestampToken> signatureTimestamps;

    /**
     * Enclosed SignAndRefs timestamps.
     */
    protected transient List<TimestampToken> sigAndRefsTimestamps;

    /**
     * Enclosed RefsOnly timestamps.
     */
    protected transient List<TimestampToken> refsOnlyTimestamps;

    /**
     * This variable contains the list of enclosed archive signature timestamps.
     */
    protected transient List<TimestampToken> archiveTimestamps;

    /**
     * This variable contains the list of detached timestamp tokens (used in ASiC with CAdES).
     */
    protected transient List<TimestampToken> detachedTimestamps;

    /**
     * A list of all TimestampedReferences extracted from a signature
     */
    protected transient List<TimestampedReference> unsignedPropertiesReferences;

    /**
     * A cached instance of Signed Signature Properties
     */
    private SignatureProperties<SA> signedSignatureProperties;

    /**
     * A cached instance of Unsigned Signature Properties
     */
    private SignatureProperties<SA> unsignedSignatureProperties;

    /**
     * Default constructor
     *
     * @param signature {@link AdvancedSignature} is being validated
     */
    protected SignatureTimestampSource(final AS signature) {
        Objects.requireNonNull(signature, "The signature cannot be null!");
        this.signature = signature;
    }

    @Override
    public List<TimestampToken> getContentTimestamps() {
        if (contentTimestamps == null) {
            createAndValidate();
        }
        return contentTimestamps;
    }

    @Override
    public List<TimestampToken> getSignatureTimestamps() {
        if (signatureTimestamps == null) {
            createAndValidate();
        }
        return signatureTimestamps;
    }

    @Override
    public List<TimestampToken> getTimestampsX1() {
        if (sigAndRefsTimestamps == null) {
            createAndValidate();
        }
        return sigAndRefsTimestamps;
    }

    @Override
    public List<TimestampToken> getTimestampsX2() {
        if (refsOnlyTimestamps == null) {
            createAndValidate();
        }
        return refsOnlyTimestamps;
    }

    @Override
    public List<TimestampToken> getArchiveTimestamps() {
        if (archiveTimestamps == null) {
            createAndValidate();
        }
        return archiveTimestamps;
    }

    @Override
    public List<TimestampToken> getDocumentTimestamps() {
        /** Applicable only for PAdES */
        return Collections.emptyList();
    }

    @Override
    public List<TimestampToken> getDetachedTimestamps() {
        if (detachedTimestamps == null) {
            createAndValidate();
        }
        return detachedTimestamps;
    }

    @Override
    public List<TimestampToken> getAllTimestamps() {
        List<TimestampToken> timestampTokens = new ArrayList<>();
        timestampTokens.addAll(getContentTimestamps());
        timestampTokens.addAll(getSignatureTimestamps());
        timestampTokens.addAll(getTimestampsX1());
        timestampTokens.addAll(getTimestampsX2());
        timestampTokens.addAll(getArchiveTimestamps());
        timestampTokens.addAll(getDetachedTimestamps());
        return timestampTokens;
    }

    @Override
    public ListCertificateSource getTimestampCertificateSources() {
        ListCertificateSource result = new ListCertificateSource();
        for (TimestampToken timestampToken : getAllTimestamps()) {
            result.add(timestampToken.getCertificateSource());
        }
        return result;
    }

    @Override
    public ListCertificateSource getTimestampCertificateSourcesExceptLastArchiveTimestamp() {
        ListCertificateSource result = new ListCertificateSource();
        List<TimestampToken> timestampTokens = getAllTimestampsExceptLastArchiveTimestamp();
        for (final TimestampToken timestampToken : timestampTokens) {
            result.add(timestampToken.getCertificateSource());
        }
        return result;
    }

    @Override
    public List<TimestampToken> getAllTimestampsExceptLastArchiveTimestamp() {
        List<TimestampToken> timestampTokens = new ArrayList<>();

        timestampTokens.addAll(getContentTimestamps());
        timestampTokens.addAll(getSignatureTimestamps());
        timestampTokens.addAll(getTimestampsX1());
        timestampTokens.addAll(getTimestampsX2());

        final List<TimestampToken> allArchiveTimestamps = new ArrayList<>();
        allArchiveTimestamps.addAll(getArchiveTimestamps());
        allArchiveTimestamps.addAll(getDocumentTimestamps()); // can be a document timestamp for PAdES
        allArchiveTimestamps.addAll(getDetachedTimestamps()); // can be a detached timestamp for ASiC with CAdES
        if (Utils.isCollectionNotEmpty(allArchiveTimestamps)) {
            if (Utils.isCollectionNotEmpty(timestampTokens) || containsTimestampsCoveringOtherTimestamps(allArchiveTimestamps)) {
                // exclude the last archive timestamp
                allArchiveTimestamps.sort(new TimestampTokenComparator());
                for (int ii = 0; ii < allArchiveTimestamps.size() - 1; ii++) {
                    TimestampToken timestampToken = allArchiveTimestamps.get(ii);
                    timestampTokens.add(timestampToken);
                }
            } else {
                // add all timestamps for validation
                timestampTokens.addAll(allArchiveTimestamps);
            }
        }
        return timestampTokens;
    }

    private boolean containsTimestampsCoveringOtherTimestamps(List<TimestampToken> timestampTokens) {
        for (TimestampToken timestampToken : timestampTokens) {
            List<TimestampedReference> timestampedReferences = timestampToken.getTimestampedReferences();
            if (Utils.isCollectionNotEmpty(timestampedReferences) &&
                    timestampedReferences.stream().anyMatch(r -> TimestampedObjectType.TIMESTAMP.equals(r.getCategory()))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public ListRevocationSource<CRL> getTimestampCRLSources() {
        ListRevocationSource<CRL> result = new ListRevocationSource<>();
        for (TimestampToken timestampToken : getAllTimestamps()) {
            result.add(timestampToken.getCRLSource());
        }
        return result;
    }

    @Override
    public ListRevocationSource<OCSP> getTimestampOCSPSources() {
        ListRevocationSource<OCSP> result = new ListRevocationSource<>();
        for (TimestampToken timestampToken : getAllTimestamps()) {
            result.add(timestampToken.getOCSPSource());
        }
        return result;
    }

    @Override
    public List<TimestampedReference> getUnsignedPropertiesReferences() {
        if (unsignedPropertiesReferences == null) {
            createAndValidate();
        }
        return unsignedPropertiesReferences;
    }

    /**
     * Creates and validates all timestamps
     * Must be called only once
     */
    protected void createAndValidate() {
        makeTimestampTokens();
        validateTimestamps();
    }

    @Override
    public void addExternalTimestamp(TimestampToken timestamp) {
        // if timestamp tokens not created yet
        if (detachedTimestamps == null) {
            createAndValidate();
        }
        processExternalTimestamp(timestamp);
        detachedTimestamps.add(timestamp);
    }

    /**
     * Populates all the lists by data found into the signature
     */
    protected void makeTimestampTokens() {
        // initialize timestamp lists
        contentTimestamps = new ArrayList<>();
        signatureTimestamps = new ArrayList<>();
        sigAndRefsTimestamps = new ArrayList<>();
        refsOnlyTimestamps = new ArrayList<>();
        archiveTimestamps = new ArrayList<>();
        detachedTimestamps = new ArrayList<>();

        // initialize combined revocation sources
        crlSource = new ListRevocationSource<>(signature.getCRLSource());
        ocspSource = new ListRevocationSource<>(signature.getOCSPSource());
        certificateSource = new ListCertificateSource(signature.getCertificateSource());

        // a list of all embedded references
        unsignedPropertiesReferences = new ArrayList<>();

        makeTimestampTokensFromSignedAttributes();
        makeTimestampTokensFromUnsignedAttributes();
    }

    /**
     * Creates TimestampTokens from all instances extracted from signed attributes
     * (content TSTs)
     */
    protected void makeTimestampTokensFromSignedAttributes() {

        SignatureProperties<SA> signedSignatureProperties = getSignedSignatureProperties();
        if (signedSignatureProperties == null || !signedSignatureProperties.isExist()) {
            return;
        }

        for (SA signedAttribute : signedSignatureProperties.getAttributes()) {

            List<TimestampToken> timestampTokens;

            if (isContentTimestamp(signedAttribute)) {
                timestampTokens = makeTimestampTokens(signedAttribute, TimestampType.CONTENT_TIMESTAMP, getSignerDataReferences());

            } else if (isAllDataObjectsTimestamp(signedAttribute)) {
                timestampTokens = makeTimestampTokens(signedAttribute, TimestampType.ALL_DATA_OBJECTS_TIMESTAMP, getSignerDataReferences());

            } else if (isIndividualDataObjectsTimestamp(signedAttribute)) {
                timestampTokens = makeTimestampTokens(signedAttribute, TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP);

            } else {
                continue;
            }

            if (Utils.isCollectionEmpty(timestampTokens)) {
                continue;
            }

            populateSources(timestampTokens);
            contentTimestamps.addAll(timestampTokens);
        }

    }

    /**
     * Creates TimestampTokens from found instances in unsigned properties
     */
    protected void makeTimestampTokensFromUnsignedAttributes() {

        final SignatureProperties<SA> unsignedSignatureProperties = getUnsignedSignatureProperties();
        if (unsignedSignatureProperties == null || !unsignedSignatureProperties.isExist()) {
            return;
        }

        final List<TimestampToken> timestamps = new ArrayList<>();

        for (SA unsignedAttribute : unsignedSignatureProperties.getAttributes()) {
            List<TimestampToken> timestampTokens;

            if (isSignatureTimestamp(unsignedAttribute)) {
                timestampTokens = makeTimestampTokens(unsignedAttribute, TimestampType.SIGNATURE_TIMESTAMP, getSignatureTimestampReferences());
                if (Utils.isCollectionEmpty(timestampTokens)) {
                    continue;
                }
                signatureTimestamps.addAll(timestampTokens);

            } else if (isCompleteCertificateRef(unsignedAttribute) || isAttributeCertificateRef(unsignedAttribute)) {
                addReferences(unsignedPropertiesReferences, getTimestampedCertificateRefs(unsignedAttribute));
                continue;

            } else if (isCompleteRevocationRef(unsignedAttribute) || isAttributeRevocationRef(unsignedAttribute)) {
                addReferences(unsignedPropertiesReferences, getTimestampedRevocationRefs(unsignedAttribute));
                continue;

            } else if (isRefsOnlyTimestamp(unsignedAttribute)) {
                final List<TimestampedReference> references = new ArrayList<>();
                addReferences(references, unsignedPropertiesReferences);

                timestampTokens = makeTimestampTokens(unsignedAttribute, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP, references);
                if (Utils.isCollectionEmpty(timestampTokens)) {
                    continue;
                }
                refsOnlyTimestamps.addAll(timestampTokens);

            } else if (isSigAndRefsTimestamp(unsignedAttribute)) {
                final List<TimestampedReference> references = new ArrayList<>();

                List<TimestampToken> signatureTimestamps = filterSignatureTimestamps(timestamps);
                addReferences(references, getEncapsulatedReferencesFromTimestamps(signatureTimestamps));
                addReferences(references, unsignedPropertiesReferences);

                timestampTokens = makeTimestampTokens(unsignedAttribute, TimestampType.VALIDATION_DATA_TIMESTAMP, references);
                if (Utils.isCollectionEmpty(timestampTokens)) {
                    continue;
                }
                sigAndRefsTimestamps.addAll(timestampTokens);

            } else if (isCertificateValues(unsignedAttribute) || isAttrAuthoritiesCertValues(unsignedAttribute)) {
                addReferences(unsignedPropertiesReferences, getTimestampedCertificateValues(unsignedAttribute));
                continue;

            } else if (isRevocationValues(unsignedAttribute) || isAttributeRevocationValues(unsignedAttribute)) {
                addReferences(unsignedPropertiesReferences, getTimestampedRevocationValues(unsignedAttribute));
                continue;

            } else if (isArchiveTimestamp(unsignedAttribute)) {
                timestampTokens = makeTimestampTokens(unsignedAttribute, TimestampType.ARCHIVE_TIMESTAMP);
                if (Utils.isCollectionEmpty(timestampTokens)) {
                    continue;
                }
                setArchiveTimestampType(timestampTokens, unsignedAttribute);
                incorporateArchiveTimestampReferences(timestampTokens, timestamps);

                archiveTimestamps.addAll(timestampTokens);

            } else if (isTimeStampValidationData(unsignedAttribute)) {
                List<TimestampedReference> timestampValidationData = getTimestampValidationData(unsignedAttribute);
                addReferences(unsignedPropertiesReferences, timestampValidationData);
                continue;

            } else if (isCounterSignature(unsignedAttribute)) {
                List<AdvancedSignature> counterSignatures = getCounterSignatures(unsignedAttribute);
                List<TimestampedReference> counterSignatureReferences = getCounterSignaturesReferences(counterSignatures);
                addReferences(unsignedPropertiesReferences, counterSignatureReferences);
                continue;

            } else if (isSignaturePolicyStore(unsignedAttribute)) {
                // not processed
                continue;

            } else {
                LOG.warn("The unsigned attribute with a name [{}] is not supported in TimestampSource processing", unsignedAttribute);
                continue;
            }

            populateSources(timestampTokens);
            timestamps.addAll(timestampTokens);
        }

    }

    /**
     * Returns the 'signed-signature-properties' element of the signature
     *
     * @return {@link SignatureProperties}
     */
    protected SignatureProperties<SA> getSignedSignatureProperties() {
        if (signedSignatureProperties == null) {
            signedSignatureProperties = buildSignedSignatureProperties();
        }
        return signedSignatureProperties;
    }

    /**
     * Creates the 'signed-signature-properties' element of the signature
     *
     * @return {@link SignatureProperties}
     */
    protected abstract SignatureProperties<SA> buildSignedSignatureProperties();

    /**
     * Returns the 'unsigned-signature-properties' element of the signature
     *
     * @return {@link SignatureProperties}
     */
    protected SignatureProperties<SA> getUnsignedSignatureProperties() {
        if (unsignedSignatureProperties == null) {
            unsignedSignatureProperties = buildUnsignedSignatureProperties();
        }
        return unsignedSignatureProperties;
    }

    /**
     * Creates the 'unsigned-signature-properties' element of the signature
     *
     * @return {@link SignatureProperties}
     */
    protected abstract SignatureProperties<SA> buildUnsignedSignatureProperties();

    /**
     * Determines if the given {@code signedAttribute} is an instance of "content-timestamp" element
     * NOTE: Applicable only for CAdES
     *
     * @param signedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is a Data Objects Timestamp, FALSE otherwise
     */
    protected abstract boolean isContentTimestamp(SA signedAttribute);

    /**
     * Determines if the given {@code signedAttribute} is an instance of "data-objects-timestamp" element
     * NOTE: Applicable only for XAdES
     *
     * @param signedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is a Data Objects Timestamp, FALSE otherwise
     */
    protected abstract boolean isAllDataObjectsTimestamp(SA signedAttribute);

    /**
     * Determines if the given {@code signedAttribute} is an instance of "individual-data-objects-timestamp" element
     * NOTE: Applicable only for XAdES
     *
     * @param signedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is a Data Objects Timestamp, FALSE otherwise
     */
    protected abstract boolean isIndividualDataObjectsTimestamp(SA signedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "signature-timestamp" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is a Signature Timestamp, FALSE otherwise
     */
    protected abstract boolean isSignatureTimestamp(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "complete-certificate-ref" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is a Complete Certificate Ref, FALSE otherwise
     */
    protected abstract boolean isCompleteCertificateRef(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "attribute-certificate-ref" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is an Attribute Certificate Ref, FALSE otherwise
     */
    protected abstract boolean isAttributeCertificateRef(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "complete-revocation-ref" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is a Complete Revocation Ref, FALSE otherwise
     */
    protected abstract boolean isCompleteRevocationRef(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "attribute-revocation-ref" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is an Attribute Revocation Ref, FALSE otherwise
     */
    protected abstract boolean isAttributeRevocationRef(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "refs-only-timestamp" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is a Refs Only TimeStamp, FALSE otherwise
     */
    protected abstract boolean isRefsOnlyTimestamp(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "sig-and-refs-timestamp" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is a Sig And Refs TimeStamp, FALSE otherwise
     */
    protected abstract boolean isSigAndRefsTimestamp(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "certificate-values" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is a Certificate Values, FALSE otherwise
     */
    protected abstract boolean isCertificateValues(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "revocation-values" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is a Revocation Values, FALSE otherwise
     */
    protected abstract boolean isRevocationValues(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "AttrAuthoritiesCertValues" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is an AttrAuthoritiesCertValues, FALSE otherwise
     */
    protected abstract boolean isAttrAuthoritiesCertValues(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "AttributeRevocationValues" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is an AttributeRevocationValues, FALSE otherwise
     */
    protected abstract boolean isAttributeRevocationValues(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of "archive-timestamp" element
     *
     * @param unsignedAttribute {@link SignatureAttribute} to process
     * @return TRUE if the {@code unsignedAttribute} is an Archive TimeStamp, FALSE otherwise
     */
    protected abstract boolean isArchiveTimestamp(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of
     * "timestamp-validation-data" element
     *
     * @param unsignedAttribute {@link SA} to process
     * @return TRUE if the {@code unsignedAttribute} is a TimeStamp Validation Data,
     * FALSE otherwise
     */
    protected abstract boolean isTimeStampValidationData(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of
     * "counter-signature" element
     *
     * @param unsignedAttribute {@link SA} to process
     * @return TRUE if the {@code unsignedAttribute} is a Counter signature, FALSE
     * otherwise
     */
    protected abstract boolean isCounterSignature(SA unsignedAttribute);

    /**
     * Determines if the given {@code unsignedAttribute} is an instance of
     * "signature-policy-store" element
     *
     * @param unsignedAttribute {@link SA} to process
     * @return TRUE if the {@code unsignedAttribute} is a Counter signature, FALSE
     * otherwise
     */
    protected abstract boolean isSignaturePolicyStore(SA unsignedAttribute);

    /**
     * Creates a timestamp token from the provided {@code signatureAttribute}
     *
     * @param signatureAttribute {@link SignatureAttribute} to create timestamp from
     * @param timestampType      a target {@link TimestampType}
     * @param references         list of {@link TimestampedReference}s covered by the current timestamp
     * @return {@link TimestampToken}
     */
    protected abstract TimestampToken makeTimestampToken(SA signatureAttribute, TimestampType timestampType,
                                                         List<TimestampedReference> references);

    /**
     * Creates timestamp tokens from the provided {@code signatureAttribute}
     *
     * @param signatureAttribute {@link SignatureAttribute} to create timestamp from
     * @param timestampType      a target {@link TimestampType}
     * @return a list of {@link TimestampToken}s
     */
    protected List<TimestampToken> makeTimestampTokens(SA signatureAttribute, TimestampType timestampType) {
        return makeTimestampTokens(signatureAttribute, timestampType, new ArrayList<>());
    }

    /**
     * Creates timestamp tokens from the provided {@code signatureAttribute}
     * with a given list of {@code TimestampedReference}s
     *
     * @param signatureAttribute {@link SignatureAttribute} to create timestamp from
     * @param timestampType      a target {@link TimestampType}
     * @param references         list of {@link TimestampedReference}s covered by the current timestamp
     * @return a list of {@link TimestampToken}s
     */
    protected List<TimestampToken> makeTimestampTokens(SA signatureAttribute, TimestampType timestampType,
                                                       List<TimestampedReference> references) {
        TimestampToken timestampToken = makeTimestampToken(signatureAttribute, timestampType, references);
        if (timestampToken != null) {
            return Collections.singletonList(timestampToken);
        }
        return Collections.emptyList();
    }

    @Override
    public List<TimestampedReference> getSignerDataReferences() {
        return getSignerDataTimestampedReferences(signature.getSignatureScopes());
    }

    /**
     * Returns a list of {@link TimestampedReference} for a "signature-timestamp" element
     *
     * @return list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getSignatureTimestampReferences() {
        final List<TimestampedReference> references = new ArrayList<>();
        addReferences(references, getEncapsulatedReferencesFromTimestamps(getContentTimestamps()));
        addReferences(references, getSignerDataReferences());
        addReference(references, new TimestampedReference(signature.getId(), TimestampedObjectType.SIGNATURE));
        addReferences(references, getSigningCertificateTimestampReferences());
        return references;
    }

    /**
     * Returns a list of TimestampedReferences for tokens encapsulated within the list of timestampTokens
     *
     * @param timestampTokens a list of {@link TimestampToken} to get references from
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getEncapsulatedReferencesFromTimestamps(List<TimestampToken> timestampTokens) {
        final List<TimestampedReference> references = new ArrayList<>();
        for (TimestampToken timestampToken : timestampTokens) {
            addReferences(references, getReferencesFromTimestamp(timestampToken, certificateSource, crlSource, ocspSource));
        }
        return references;
    }

    /**
     * Returns a list of {@code TimestampedReference}s created from signing certificates of the signature
     *
     * @return list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getSigningCertificateTimestampReferences() {
        SignatureCertificateSource signatureCertificateSource = signature.getCertificateSource();
        return createReferencesForCertificateRefs(signatureCertificateSource.getSigningCertificateRefs(),
                signatureCertificateSource, certificateSource);
    }

    /**
     * Returns references from the KeyInfo (for XAdES) encapsulated elements
     *
     * @return list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getKeyInfoReferences() {
        SignatureCertificateSource signatureCertificateSource = signature.getCertificateSource();
        return createReferencesForCertificates(signatureCertificateSource.getKeyInfoCertificates());
    }

    /**
     * Returns a list of {@link TimestampedReference} certificate refs found in the
     * given {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to find references from
     * @return list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getTimestampedCertificateRefs(SA unsignedAttribute) {
        return createReferencesForCertificateRefs(getCertificateRefs(unsignedAttribute),
                signature.getCertificateSource(), certificateSource);
    }

    /**
     * Returns a list of {@link CertificateRef}s from the given
     * {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to get certRefs from
     * @return list of {@link CertificateRef}s
     */
    protected abstract List<CertificateRef> getCertificateRefs(SA unsignedAttribute);

    /**
     * Returns a list of {@link TimestampedReference} revocation refs found in the given {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to find references from
     * @return list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getTimestampedRevocationRefs(SA unsignedAttribute) {
        List<TimestampedReference> timestampedReferences = new ArrayList<>();
        timestampedReferences.addAll(createReferencesForCRLRefs(getCRLRefs(unsignedAttribute),
                signature.getCRLSource(), crlSource));
        timestampedReferences.addAll(createReferencesForOCSPRefs(getOCSPRefs(unsignedAttribute),
                signature.getOCSPSource(), certificateSource, ocspSource));
        return timestampedReferences;
    }

    /**
     * Returns a list of CRL revocation refs from the given
     * {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to get CRLRef
     * @return list of {@link CRLRef}s
     */
    protected abstract List<CRLRef> getCRLRefs(SA unsignedAttribute);

    /**
     * Returns a list of OCSP revocation refs from the given
     * {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to get OCSPRefs from
     * @return list of {@link OCSPRef}s
     */
    protected abstract List<OCSPRef> getOCSPRefs(SA unsignedAttribute);

    /**
     * Returns a list of {@code TimestampedReference}s from the {@code unsignedAttribute} containing certificate values
     *
     * @param unsignedAttribute {@link SA} to extract certificate values from
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getTimestampedCertificateValues(SA unsignedAttribute) {
        return createReferencesForIdentifiers(getEncapsulatedCertificateIdentifiers(unsignedAttribute), TimestampedObjectType.CERTIFICATE);
    }

    /**
     * Returns a list of {@link Identifier}s obtained from the given {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to get certificate identifiers from
     * @return list of {@link Identifier}s
     */
    protected abstract List<Identifier> getEncapsulatedCertificateIdentifiers(SA unsignedAttribute);

    /**
     * Returns a list of timestamped revocation references extracted from the given unsigned attribute
     *
     * @param unsignedAttribute {@link SA} containing revocation data
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getTimestampedRevocationValues(SA unsignedAttribute) {
        final List<TimestampedReference> timestampedReferences = new ArrayList<>();
        timestampedReferences.addAll(createReferencesForCRLBinaries(getEncapsulatedCRLIdentifiers(unsignedAttribute)));
        timestampedReferences.addAll(createReferencesForOCSPBinaries(getEncapsulatedOCSPIdentifiers(unsignedAttribute), certificateSource));
        return timestampedReferences;
    }

    /**
     * Returns a list of {@link CRLBinary}s obtained from the given {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to get CRL identifiers from
     * @return list of {@link CRLBinary}s
     */
    protected abstract List<CRLBinary> getEncapsulatedCRLIdentifiers(SA unsignedAttribute);

    /**
     * Returns a list of {@link OCSPResponseBinary}s obtained from the given {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to get OCSP identifiers from
     * @return list of {@link OCSPResponseBinary}s
     */
    protected abstract List<OCSPResponseBinary> getEncapsulatedOCSPIdentifiers(SA unsignedAttribute);

    private void incorporateArchiveTimestampReferences(List<TimestampToken> createdTimestampTokens,
                                                       List<TimestampToken> previousTimestamps) {
        for (TimestampToken timestampToken : createdTimestampTokens) {
            incorporateArchiveTimestampReferences(timestampToken, previousTimestamps);
        }
    }

    /**
     * The method incorporates all the timestamped references for
     * the given archive {@code timestampToken}
     *
     * @param timestampToken     {@link TimestampToken} representing an Archive TST
     *                           to add references into
     * @param previousTimestamps a list of previously created
     *                           {@link TimestampToken}s
     */
    protected void incorporateArchiveTimestampReferences(TimestampToken timestampToken,
                                                         List<TimestampToken> previousTimestamps) {
        addReferences(timestampToken.getTimestampedReferences(), getSignatureTimestampReferences());
        addReferences(timestampToken.getTimestampedReferences(), getEncapsulatedReferencesFromTimestamps(previousTimestamps));
        addReferences(timestampToken.getTimestampedReferences(), unsignedPropertiesReferences);
        addReferences(timestampToken.getTimestampedReferences(), getArchiveTimestampOtherReferences(timestampToken));
    }

    /**
     * Returns a list of {@code TimestampedReference}s for the given archive {@code timestampToken}
     * that cannot be extracted from signature attributes (signed or unsigned),
     * depending on its format (signedData for CAdES or, keyInfo for XAdES)
     *
     * @param timestampToken {@link TimestampToken} to get archive timestamp references for
     * @return list of {@link TimestampedReference}s
     */
    protected abstract List<TimestampedReference> getArchiveTimestampOtherReferences(TimestampToken timestampToken);

    /**
     * Returns a list of all {@code TimestampedReference}s found into CMS SignedData of the signature
     * NOTE: used only in ASiC-E CAdES
     *
     * @return list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getSignatureSignedDataReferences() {
        // empty by default
        return new ArrayList<>();
    }

    /**
     * Returns a list of {@link TimestampedReference}s encapsulated to the "timestamp-validation-data" {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to get timestamped references from
     * @return list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getTimestampValidationData(SA unsignedAttribute) {
        final List<TimestampedReference> timestampedReferences = new ArrayList<>();
        addReferences(timestampedReferences, createReferencesForIdentifiers(
                getEncapsulatedCertificateIdentifiers(unsignedAttribute), TimestampedObjectType.CERTIFICATE));
        addReferences(timestampedReferences, createReferencesForCRLBinaries(getEncapsulatedCRLIdentifiers(unsignedAttribute)));
        addReferences(timestampedReferences, createReferencesForOCSPBinaries(getEncapsulatedOCSPIdentifiers(unsignedAttribute), certificateSource));
        return timestampedReferences;
    }

    /**
     * Returns a list of {@link TimestampedReference}s encapsulated from the list of counter signatures
     *
     * @param counterSignatures a list of {@link AdvancedSignature} to get timestamped references from
     * @return list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getCounterSignaturesReferences(List<AdvancedSignature> counterSignatures) {
        List<TimestampedReference> references = new ArrayList<>();

        if (Utils.isCollectionNotEmpty(counterSignatures)) {
            for (AdvancedSignature counterSignature : counterSignatures) {
                references.addAll(getCounterSignatureReferences(counterSignature));
            }
        }

        return references;
    }

    /**
     * Returns a list of references extracted from a counter signature
     *
     * @param counterSignature {@link AdvancedSignature} representing a counter signature
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getCounterSignatureReferences(AdvancedSignature counterSignature) {
        List<TimestampedReference> counterSigReferences = new ArrayList<>();

        counterSigReferences.add(new TimestampedReference(counterSignature.getId(), TimestampedObjectType.SIGNATURE));

        SignatureCertificateSource signatureCertificateSource = counterSignature.getCertificateSource();
        addReferences(counterSigReferences, createReferencesForCertificates(signatureCertificateSource.getCertificates()));

        TimestampSource counterSignatureTimestampSource = counterSignature.getTimestampSource();
        addReferences(counterSigReferences, counterSignatureTimestampSource.getSignerDataReferences());
        addReferences(counterSigReferences, counterSignatureTimestampSource.getUnsignedPropertiesReferences());
        addReferences(counterSigReferences, getEncapsulatedReferencesFromTimestamps(
                counterSignatureTimestampSource.getAllTimestamps()));

        return counterSigReferences;
    }

    /**
     * Extracts Counter Signatures from the given {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} containing counter signatures
     * @return a list of {@link AdvancedSignature} containing counter signatures
     */
    protected abstract List<AdvancedSignature> getCounterSignatures(SA unsignedAttribute);

    private List<TimestampToken> filterSignatureTimestamps(List<TimestampToken> previousTimestampedTimestamp) {
        List<TimestampToken> result = new ArrayList<>();
        for (TimestampToken timestampToken : previousTimestampedTimestamp) {
            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampToken.getTimeStampType())) {
                result.add(timestampToken);
            }
        }
        return result;
    }

    private void setArchiveTimestampType(List<TimestampToken> timestampTokens, SA unsignedAttribute) {
        ArchiveTimestampType archiveTimestampType = getArchiveTimestampType(unsignedAttribute);
        for (TimestampToken timestampToken : timestampTokens) {
            timestampToken.setArchiveTimestampType(archiveTimestampType);
        }
    }

    /**
     * Returns {@link ArchiveTimestampType} for the given {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to get archive timestamp type for
     * @return {@link ArchiveTimestampType}
     */
    protected abstract ArchiveTimestampType getArchiveTimestampType(SA unsignedAttribute);

    /**
     * Validates list of all timestamps present in the source
     */
    protected void validateTimestamps() {

        DSSMessageDigest messageDigest = null;

        /*
         * This validates the content-timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : getContentTimestamps()) {
            messageDigest = getTimestampMessageImprintDigestBuilder(timestampToken).getContentTimestampMessageDigest();
            timestampToken.matchData(messageDigest);
            timestampToken.setTimestampScopes(getTimestampScopes(timestampToken));
        }

        /*
         * This validates the signature timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : getSignatureTimestamps()) {
            messageDigest = getTimestampMessageImprintDigestBuilder(timestampToken).getSignatureTimestampMessageDigest();
            timestampToken.matchData(messageDigest);
        }

        /*
         * This validates the SigAndRefs timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : getTimestampsX1()) {
            messageDigest = getTimestampMessageImprintDigestBuilder(timestampToken).getTimestampX1MessageDigest();
            timestampToken.matchData(messageDigest);
        }

        /*
         * This validates the RefsOnly timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : getTimestampsX2()) {
            messageDigest = getTimestampMessageImprintDigestBuilder(timestampToken).getTimestampX2MessageDigest();
            timestampToken.matchData(messageDigest);
        }

        /*
         * This validates the archive timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : getArchiveTimestamps()) {
            if (!timestampToken.isProcessed()) {
                messageDigest = getTimestampMessageImprintDigestBuilder(timestampToken).getArchiveTimestampMessageDigest();
                timestampToken.matchData(messageDigest);
                timestampToken.setTimestampScopes(getTimestampScopes(timestampToken));
            }
        }

    }

    /**
     * Returns a {@link TimestampMessageDigestBuilder} to compute message digest
     * with the provided {@code DigestAlgorithm}
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to use for message-digest computation
     * @return {@link TimestampMessageDigestBuilder}
     */
    protected abstract TimestampMessageDigestBuilder getTimestampMessageImprintDigestBuilder(
            DigestAlgorithm digestAlgorithm);

    /**
     * Returns a related {@link TimestampMessageDigestBuilder}
     *
     * @param timestampToken {@link TimestampToken} to get message-imprint digest builder for
     * @return {@link TimestampMessageDigestBuilder}
     */
    protected abstract TimestampMessageDigestBuilder getTimestampMessageImprintDigestBuilder(TimestampToken timestampToken);

    /**
     * Generates timestamp token scopes
     *
     * @param timestampToken {@link TimestampToken} to get timestamp sources for
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> getTimestampScopes(TimestampToken timestampToken) {
        EncapsulatedTimestampScopeFinder timestampScopeFinder = new EncapsulatedTimestampScopeFinder();
        timestampScopeFinder.setSignature(signature);
        return timestampScopeFinder.findTimestampScope(timestampToken);
    }

    private void processExternalTimestamp(TimestampToken externalTimestamp) {
        // add all validation data present in Signature CMS SignedData, because an external timestamp covers a whole signature file
        addReferences(externalTimestamp.getTimestampedReferences(), getSignatureSignedDataReferences());
        // add references from previously added timestamps
        addReferences(externalTimestamp.getTimestampedReferences(), getEncapsulatedReferencesFromTimestamps(
                getTimestampsCoveredByExternalTimestamp(externalTimestamp)));
        // add existing counter signatures
        addReferences(externalTimestamp.getTimestampedReferences(), getCounterSignatureReferences(signature));
        // populate timestamp certificate source with values present in the timestamp
        populateSources(externalTimestamp);
    }

    private List<TimestampToken> getTimestampsCoveredByExternalTimestamp(TimestampToken externalTimestamp) {
        List<TimestampToken> result = new ArrayList<>();
        for (TimestampToken timestampToken : getAllTimestamps()) {
            if (detachedTimestamps.contains(timestampToken)) {
                ManifestFile manifestFile = externalTimestamp.getManifestFile();
                if (manifestFile == null || !manifestFile.isDocumentCovered(timestampToken.getFileName())) {
                    // the detached timestamp is not covered, continue
                    continue;
                }
            }
            result.add(timestampToken);
        }
        return result;
    }

    /**
     * Allows to populate all merged sources with extracted from a timestamp data
     *
     * @param timestampTokens a list of {@link TimestampToken}s to populate data from
     */
    protected void populateSources(List<TimestampToken> timestampTokens) {
        for (TimestampToken timestampToken : timestampTokens) {
            populateSources(timestampToken);
        }
    }

    /**
     * Allows to populate all merged sources with extracted from a timestamp data
     *
     * @param timestampToken {@link TimestampToken} to populate data from
     */
    protected void populateSources(TimestampToken timestampToken) {
        if (timestampToken != null) {
            certificateSource.add(timestampToken.getCertificateSource());
            crlSource.add(timestampToken.getCRLSource());
            ocspSource.add(timestampToken.getOCSPSource());
        }
    }

    @Override
    public boolean isTimestamped(String tokenId, TimestampedObjectType objectType) {
        return isTimestamped(signature, tokenId, objectType);
    }

    private boolean isTimestamped(AdvancedSignature signature, String tokenId, TimestampedObjectType objectType) {
        for (TimestampToken timestampToken : getAllTimestamps()) {
            if (timestampToken.getTimestampedReferences().contains(new TimestampedReference(tokenId, objectType))) {
                return true;
            }
        }
        AdvancedSignature masterSignature = signature.getMasterSignature();
        if (masterSignature != null) {
            return isTimestamped(masterSignature, tokenId, objectType);
        }

        return false;
    }

}
