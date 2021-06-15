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

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLRef;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRef;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.ListRevocationSource;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignatureAttribute;
import eu.europa.esig.dss.validation.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignatureProperties;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * The timestamp source of a signature
 *
 * @param <AS> {@code AdvancedSignature} implementation
 * @param <SA> the corresponding {@code SignatureAttribute}
 */
public abstract class SignatureTimestampSource<AS extends AdvancedSignature, SA extends SignatureAttribute>
        extends AbstractTimestampSource implements TimestampSource {

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
    protected List<TimestampToken> contentTimestamps;

    /**
     * Enclosed signature timestamps.
     */
    protected List<TimestampToken> signatureTimestamps;

    /**
     * Enclosed SignAndRefs timestamps.
     */
    protected List<TimestampToken> sigAndRefsTimestamps;

    /**
     * Enclosed RefsOnly timestamps.
     */
    protected List<TimestampToken> refsOnlyTimestamps;

    /**
     * This variable contains the list of enclosed archive signature timestamps.
     */
    protected List<TimestampToken> archiveTimestamps;

    /**
     * This variable contains the list of detached timestamp tokens (used in ASiC with CAdES).
     */
    protected List<TimestampToken> detachedTimestamps;

    /**
     * A list of all TimestampedReferences extracted from a signature
     */
    protected List<TimestampedReference> unsignedPropertiesReferences;

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
        timestampTokens.addAll(getDocumentTimestamps());
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

        final List<TimestampToken> archiveTimestamps = new ArrayList<>(getArchiveTimestamps());
        archiveTimestamps.addAll(getDocumentTimestamps()); // can be a document timestamp for PAdES
        archiveTimestamps.addAll(getDetachedTimestamps()); // can be a detached timestamp for ASiC with CAdES
        Collections.sort(archiveTimestamps, new TimestampTokenComparator());
        if (archiveTimestamps.size() > 0) {
            for (int ii = 0; ii < archiveTimestamps.size() - 1; ii++) {
                TimestampToken timestampToken = archiveTimestamps.get(ii);
                timestampTokens.add(timestampToken);
            }
        }
        return timestampTokens;
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
                if (Utils.isCollectionEmpty(timestampTokens)) {
                    continue;
                }

            } else if (isAllDataObjectsTimestamp(signedAttribute)) {
                timestampTokens = makeTimestampTokens(signedAttribute, TimestampType.ALL_DATA_OBJECTS_TIMESTAMP, getSignerDataReferences());
                if (Utils.isCollectionEmpty(timestampTokens)) {
                    continue;
                }

            } else if (isIndividualDataObjectsTimestamp(signedAttribute)) {
                List<TimestampedReference> references = getIndividualContentTimestampedReferences(signedAttribute);
                timestampTokens = makeTimestampTokens(signedAttribute, TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP, references);
                if (Utils.isCollectionEmpty(timestampTokens)) {
                    continue;
                }

            } else {
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

            } else if (isCompleteCertificateRef(unsignedAttribute)) {
                addReferences(unsignedPropertiesReferences, getTimestampedCertificateRefs(unsignedAttribute));
                continue;

            } else if (isAttributeCertificateRef(unsignedAttribute)) {
                addReferences(unsignedPropertiesReferences, getTimestampedCertificateRefs(unsignedAttribute));
                continue;

            } else if (isCompleteRevocationRef(unsignedAttribute)) {
                addReferences(unsignedPropertiesReferences, getTimestampedRevocationRefs(unsignedAttribute));
                continue;

            } else if (isAttributeRevocationRef(unsignedAttribute)) {
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

            } else if (isCertificateValues(unsignedAttribute)) {
                addReferences(unsignedPropertiesReferences, getTimestampedCertificateValues(unsignedAttribute));
                continue;

            } else if (isRevocationValues(unsignedAttribute)) {
                addReferences(unsignedPropertiesReferences, getTimestampedRevocationValues(unsignedAttribute));
                continue;

            } else if (isAttrAuthoritiesCertValues(unsignedAttribute)) {
                addReferences(unsignedPropertiesReferences, getTimestampedCertificateValues(unsignedAttribute));
                continue;

            } else if (isAttributeRevocationValues(unsignedAttribute)) {
                addReferences(unsignedPropertiesReferences, getTimestampedRevocationValues(unsignedAttribute));
                continue;

            } else if (isArchiveTimestamp(unsignedAttribute)) {
                timestampTokens = makeTimestampTokens(unsignedAttribute, TimestampType.ARCHIVE_TIMESTAMP,
                        new ArrayList<>());
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
        final List<TimestampedReference> references = new ArrayList<>();
        populateSignerDataReferencesList(references, signature.getSignatureScopes());
        return references;
    }

    /**
     * Populates the {@code result} list with references creates from the {@code signatureScopes} list
     *
     * @param result a final list of {@link TimestampedReference} to populate
     * @param signatureScopes a list of {@link SignatureScope} to use
     */
    protected void populateSignerDataReferencesList(final List<TimestampedReference> result, List<SignatureScope> signatureScopes) {
        if (Utils.isCollectionNotEmpty(signatureScopes)) {
            for (SignatureScope signatureScope : signatureScopes) {
                addReference(result, new TimestampedReference(signatureScope.getDSSIdAsString(), TimestampedObjectType.SIGNED_DATA));
                if (Utils.isCollectionNotEmpty(signatureScope.getChildren())) {
                    populateSignerDataReferencesList(result, signatureScope.getChildren());
                }
            }
        }
    }

    /**
     * Returns a list of {@link TimestampedReference}s for an "individual-data-objects-timestamp"
     * NOTE: Used only in XAdES
     *
     * @param signedAttribute {@link SA}
     * @return a list of {@link TimestampedReference}s
     */
    protected abstract List<TimestampedReference> getIndividualContentTimestampedReferences(SA signedAttribute);

    /**
     * Returns a list of {@link TimestampedReference} for a "signature-timestamp" element
     *
     * @return list of {@link TimestampedReference}s
     */
    public List<TimestampedReference> getSignatureTimestampReferences() {
        final List<TimestampedReference> references = new ArrayList<>();
        addReferences(references, getEncapsulatedReferencesFromTimestamps(getContentTimestamps()));
        addReferences(references, getSignerDataReferences());
        addReference(references, new TimestampedReference(signature.getId(), TimestampedObjectType.SIGNATURE));
        addReferences(references, getSigningCertificateTimestampReferences());
        return references;
    }

    /**
     * Returns a list of {@code TimestampedReference}s created from signing certificates of the signature
     *
     * @return list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getSigningCertificateTimestampReferences() {
        SignatureCertificateSource signatureCertificateSource = signature.getCertificateSource();
        return getTimestampedCertificateRefs(signatureCertificateSource.getSigningCertificateRefs(), certificateSource);
    }

    /**
     * Returns a list of {@link TimestampedReference} certificate refs found in the
     * given {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to find references from
     * @return list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getTimestampedCertificateRefs(SA unsignedAttribute) {
        return getTimestampedCertificateRefs(getCertificateRefs(unsignedAttribute), certificateSource);
    }

    /**
     * Returns a list of timestamped references from the given collection of {@code certificateRefs}
     *
     * @param certificateRefs       a collection of {@link CertificateRef}s to get timestamped references from
     * @param listCertificateSource {@link ListCertificateSource} to find certificate binaries from if present
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getTimestampedCertificateRefs(Collection<CertificateRef> certificateRefs, ListCertificateSource listCertificateSource) {
        List<TimestampedReference> timestampedReferences = new ArrayList<>();
        for (CertificateRef certRef : certificateRefs) {
            Set<CertificateToken> certificateTokens = listCertificateSource.findTokensFromRefs(certRef);
            if (Utils.isCollectionNotEmpty(certificateTokens)) {
                for (CertificateToken token : certificateTokens) {
                    timestampedReferences.add(new TimestampedReference(token.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
                }
            } else {
                timestampedReferences.add(new TimestampedReference(certRef.getDSSIdAsString(), TimestampedObjectType.CERTIFICATE));
            }
        }
        return timestampedReferences;
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
        timestampedReferences.addAll(getTimestampedCRLRefs(getCRLRefs(unsignedAttribute), crlSource));
        timestampedReferences.addAll(getTimestampedOCSPRefs(getOCSPRefs(unsignedAttribute), ocspSource));
        return timestampedReferences;
    }

    /**
     * Returns a list of timestamped references from the given collection of {@code crlRefs}
     *
     * @param crlRefs             a collection of {@link CRLRef}s to get timestamped references from
     * @param crlRevocationSource {@link ListRevocationSource} to find CRL binaries from if present
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getTimestampedCRLRefs(Collection<? extends RevocationRef<CRL>> crlRefs, ListRevocationSource<CRL> crlRevocationSource) {
        List<TimestampedReference> timestampedReferences = new ArrayList<>();
        for (RevocationRef<CRL> crlRef : crlRefs) {
            EncapsulatedRevocationTokenIdentifier<CRL> token = crlRevocationSource.findBinaryForReference(crlRef);
            if (token != null) {
                timestampedReferences.add(new TimestampedReference(token.asXmlId(), TimestampedObjectType.REVOCATION));
            } else {
                timestampedReferences.add(new TimestampedReference(crlRef.getDSSIdAsString(), TimestampedObjectType.REVOCATION));
            }
        }
        return timestampedReferences;
    }

    /**
     * Returns a list of timestamped references from the given collection of {@code ocspRefs}
     *
     * @param ocspRefs             a collection of {@link OCSPRef}s to get timestamped references from
     * @param ocspRevocationSource {@link ListRevocationSource} to find OCSP binaries from if present
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getTimestampedOCSPRefs(Collection<? extends RevocationRef<OCSP>> ocspRefs, ListRevocationSource<OCSP> ocspRevocationSource) {
        List<TimestampedReference> timestampedReferences = new ArrayList<>();
        for (RevocationRef<OCSP> ocspRef : ocspRefs) {
            EncapsulatedRevocationTokenIdentifier<OCSP> token = ocspRevocationSource.findBinaryForReference(ocspRef);
            if (token != null) {
                timestampedReferences.add(new TimestampedReference(token.asXmlId(), TimestampedObjectType.REVOCATION));
            } else {
                timestampedReferences.add(new TimestampedReference(ocspRef.getDSSIdAsString(), TimestampedObjectType.REVOCATION));
            }
        }
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
        List<TimestampedReference> timestampedReferences = new ArrayList<>();
        timestampedReferences.addAll(createReferencesForIdentifiers(getEncapsulatedCRLIdentifiers(unsignedAttribute), TimestampedObjectType.REVOCATION));
        timestampedReferences.addAll(createReferencesForIdentifiers(getEncapsulatedOCSPIdentifiers(unsignedAttribute), TimestampedObjectType.REVOCATION));
        return timestampedReferences;
    }

    /**
     * Returns a list of {@link Identifier}s obtained from the given {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to get CRL identifiers from
     * @return list of {@link Identifier}s
     */
    protected abstract List<Identifier> getEncapsulatedCRLIdentifiers(SA unsignedAttribute);

    /**
     * Returns a list of {@link Identifier}s obtained from the given {@code unsignedAttribute}
     *
     * @param unsignedAttribute {@link SA} to get OCSP identifiers from
     * @return list of {@link Identifier}s
     */
    protected abstract List<Identifier> getEncapsulatedOCSPIdentifiers(SA unsignedAttribute);

    /**
     * Returns a list of {@code TimestampedReference}s that has been extracted from
     * previously incorporated signed and unsigned elements
     *
     * @param unsignedAttribute  {@link SA} representing a timestamp
     * @param previousTimestamps a list of previously created {@link TimestampToken}
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getArchiveTimestampInitialReferences(SA unsignedAttribute,
                                                                              List<TimestampToken> previousTimestamps) {
        final List<TimestampedReference> references = new ArrayList<>();
        addReferences(references, getSignatureTimestampReferences());
        addReferences(references, getEncapsulatedReferencesFromTimestamps(previousTimestamps));
        addReferences(references, getSignerDataReferences());
        addReferences(references, unsignedPropertiesReferences);
        return references;
    }

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
        List<TimestampedReference> timestampedReferences = new ArrayList<>();

        List<TimestampedReference> certTimestampedReferences = createReferencesForIdentifiers(
                getEncapsulatedCertificateIdentifiers(unsignedAttribute), TimestampedObjectType.CERTIFICATE);
        timestampedReferences.addAll(certTimestampedReferences);

        List<TimestampedReference> crlTimestampedReferences = createReferencesForIdentifiers(
                getEncapsulatedCRLIdentifiers(unsignedAttribute), TimestampedObjectType.REVOCATION);
        timestampedReferences.addAll(crlTimestampedReferences);

        List<TimestampedReference> ocspTimestampedReferences = createReferencesForIdentifiers(
                getEncapsulatedOCSPIdentifiers(unsignedAttribute), TimestampedObjectType.REVOCATION);
        timestampedReferences.addAll(ocspTimestampedReferences);

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
     * Returns a list of references extracted from a coutner signature
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

        TimestampDataBuilder timestampDataBuilder = getTimestampDataBuilder();

        /*
         * This validates the content-timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : getContentTimestamps()) {
            final DSSDocument timestampedData = timestampDataBuilder.getContentTimestampData(timestampToken);
            timestampToken.matchData(timestampedData);
        }

        /*
         * This validates the signature timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : getSignatureTimestamps()) {
            final DSSDocument timestampedData = timestampDataBuilder.getSignatureTimestampData(timestampToken);
            timestampToken.matchData(timestampedData);
        }

        /*
         * This validates the SigAndRefs timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : getTimestampsX1()) {
            final DSSDocument timestampedData = timestampDataBuilder.getTimestampX1Data(timestampToken);
            timestampToken.matchData(timestampedData);
        }

        /*
         * This validates the RefsOnly timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : getTimestampsX2()) {
            final DSSDocument timestampedData = timestampDataBuilder.getTimestampX2Data(timestampToken);
            timestampToken.matchData(timestampedData);
        }

        /*
         * This validates the archive timestamp tokensToProcess present in the signature.
         */
        for (final TimestampToken timestampToken : getArchiveTimestamps()) {
            if (!timestampToken.isProcessed()) {
                final DSSDocument timestampedData = timestampDataBuilder.getArchiveTimestampData(timestampToken);
                timestampToken.matchData(timestampedData);
            }
        }

    }

    /**
     * Returns a related {@link TimestampDataBuilder}
     *
     * @return {@link TimestampDataBuilder}
     */
    protected abstract TimestampDataBuilder getTimestampDataBuilder();

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
