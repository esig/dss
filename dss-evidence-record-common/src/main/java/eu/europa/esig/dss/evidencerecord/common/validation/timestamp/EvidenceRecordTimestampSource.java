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
package eu.europa.esig.dss.evidencerecord.common.validation.timestamp;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.CryptographicInformation;
import eu.europa.esig.dss.evidencerecord.common.validation.CryptographicInformationType;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.validation.scope.EvidenceRecordTimestampScopeFinder;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ListRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class is used for extraction and validation of time-stamps incorporated within an Evidence Record
 *
 * @param <ER> {@code DefaultEvidenceRecord}
 */
public abstract class EvidenceRecordTimestampSource<ER extends DefaultEvidenceRecord> extends AbstractTimestampSource {

    private static final Logger LOG = LoggerFactory.getLogger(EvidenceRecordTimestampSource.class);

    /**
     * The evidence record to be validated
     */
    protected final ER evidenceRecord;

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
     * Enclosed timestamps
     */
    protected List<TimestampToken> timestamps;

    /**
     * This variable contains the list of detached evidence record tokens covering the evidence record.
     */
    protected List<EvidenceRecord> detachedEvidenceRecords;

    /**
     * Default constructor to instantiate a time-stamp source from an evidence record
     *
     * @param evidenceRecord {@link EvidenceRecord}
     */
    protected EvidenceRecordTimestampSource(ER evidenceRecord) {
        Objects.requireNonNull(evidenceRecord, "The evidence record cannot be null!");
        this.evidenceRecord = evidenceRecord;
    }

    /**
     * Returns a list of found {@code TimestampToken}s
     *
     * @return a list of {@code TimestampToken}s
     */
    public List<TimestampToken> getTimestamps() {
        if (timestamps == null) {
            createAndValidate();
        }
        return timestamps;
    }

    /**
     * Returns a list of detached evidence records covering the evidence record
     *
     * @return a list of {@link EvidenceRecord}s
     */
    public List<EvidenceRecord> getDetachedEvidenceRecords() {
        if (detachedEvidenceRecords == null) {
            createAndValidate();
        }
        return detachedEvidenceRecords;
    }

    public void addExternalEvidenceRecord(EvidenceRecord evidenceRecord) {
        // if timestamp tokens not created yet
        if (detachedEvidenceRecords == null) {
            createAndValidate();
        }
        processExternalEvidenceRecord(evidenceRecord);
        detachedEvidenceRecords.add(evidenceRecord);
    }

    /**
     * Creates and validates all timestamps
     * Must be called only once
     */
    protected void createAndValidate() {
        timestamps = new ArrayList<>();
        detachedEvidenceRecords = new ArrayList<>();

        // initialize combined revocation sources
        crlSource = new ListRevocationSource<>(evidenceRecord.getCRLSource());
        ocspSource = new ListRevocationSource<>(evidenceRecord.getOCSPSource());
        certificateSource = new ListCertificateSource(evidenceRecord.getCertificateSource());

        final List<TimestampedReference> signerDataReferences = getSignerDataReferences();
        final List<TimestampedReference> erValidationDataReferences = new ArrayList<>();

        List<TimestampedReference> previousTimestampReferences = new ArrayList<>();
        List<TimestampedReference> previousChainTimestampReferences = new ArrayList<>();

        List<TimestampedReference> references = new ArrayList<>();

        for (ArchiveTimeStampChainObject archiveTimeStampChain : evidenceRecord.getArchiveTimeStampSequence()) {

            addReferences(references, signerDataReferences);
            addReference(references, getEvidenceRecordReference());
            addReferences(references, previousChainTimestampReferences);
            previousChainTimestampReferences = new ArrayList<>();

            for (ArchiveTimeStampObject archiveTimeStamp : archiveTimeStampChain.getArchiveTimeStamps()) {

                addReferences(references, previousTimestampReferences);
                addReferences(references, erValidationDataReferences);
                previousTimestampReferences = new ArrayList<>();

                TimestampToken timestampToken = createTimestampToken(archiveTimeStamp);
                timestampToken.getTimestampedReferences().addAll(references);
                timestampToken.setTimestampScopes(findTimestampScopes(timestampToken));

                // add time-stamp token
                populateSources(timestampToken);
                timestamps.add(timestampToken);

                List<TimestampedReference> encapsulatedTimestampReferences = getEncapsulatedReferencesFromTimestamp(timestampToken);
                addReferences(previousTimestampReferences, encapsulatedTimestampReferences);
                addReferences(previousChainTimestampReferences, encapsulatedTimestampReferences);

                List<CryptographicInformation> cryptographicInformationList = archiveTimeStamp.getCryptographicInformationList();
                addReferences(erValidationDataReferences, getEncapsulatedReferencesFromCryptographicInformationList(cryptographicInformationList));

                // clear references for the next time-stamp token
                references = new ArrayList<>();
            }
        }
    }

    /**
     * This method is used to create a {@code TimestampToken} from {@code ArchiveTimeStampObject}
     *
     * @param archiveTimeStamp {@link ArchiveTimeStampObject} to extract time-stamp token from
     * @return {@link TimestampToken}
     */
    protected TimestampToken createTimestampToken(ArchiveTimeStampObject archiveTimeStamp) {
        return archiveTimeStamp.getTimestampToken();
    }

    /**
     * Creates a evidence record reference for the current signature
     *
     * @return {@link TimestampedReference}
     */
    protected TimestampedReference getEvidenceRecordReference() {
        return new TimestampedReference(evidenceRecord.getId(), TimestampedObjectType.EVIDENCE_RECORD);
    }

    /**
     * Returns a list of timestamped references for signed data objects
     *
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getSignerDataReferences() {
        List<SignatureScope> evidenceRecordScopes = evidenceRecord.getEvidenceRecordScopes();
        if (Utils.isCollectionEmpty(evidenceRecordScopes)) {
            return Collections.emptyList();
        }
        return getSignerDataTimestampedReferences(evidenceRecordScopes);
    }

    /**
     * Returns a list of TimestampedReferences for tokens encapsulated within the time-stamp token
     *
     * @param timestampToken {@link TimestampToken} to get references from
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getEncapsulatedReferencesFromTimestamp(TimestampToken timestampToken) {
        return getReferencesFromTimestamp(timestampToken, certificateSource, crlSource, ocspSource);
    }

    /**
     * Finds timestamp scopes
     *
     * @param timestampToken {@link TimestampToken} to get timestamp scopes for
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> findTimestampScopes(TimestampToken timestampToken) {
        return new EvidenceRecordTimestampScopeFinder(evidenceRecord).findTimestampScope(timestampToken);
    }

    private void processExternalEvidenceRecord(EvidenceRecord externalEvidenceRecord) {
        // add reference to the covered evidence record
        addReference(externalEvidenceRecord.getTimestampedReferences(), getEvidenceRecordReference());
        // add references from covered evidence record
        addReferences(externalEvidenceRecord.getTimestampedReferences(), evidenceRecord.getTimestampedReferences());
        // add references from evidence record timestamps
        addReferences(externalEvidenceRecord.getTimestampedReferences(), getEncapsulatedReferencesFromTimestamps(getTimestamps()));
        // extract validation data
        populateSources(externalEvidenceRecord);
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
     * Returns a list of TimestampedReferences for tokens encapsulated within the CryptographicInformationList element in Evidence Record
     *
     * @param cryptographicInformationList a list of {@link CryptographicInformation}s
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getEncapsulatedReferencesFromCryptographicInformationList(List<CryptographicInformation> cryptographicInformationList) {
        if (Utils.isCollectionEmpty(cryptographicInformationList)) {
            return Collections.emptyList();
        }

        final List<TimestampedReference> references = new ArrayList<>();

        List<CertificateToken> certificateTokens = getEncapsulatedCertificateTokens(cryptographicInformationList);
        addReferences(references, createReferencesForCertificates(certificateTokens));

        List<CRLBinary> crlBinaries = getEncapsulatedCRLBinaries(cryptographicInformationList);
        addReferences(references, createReferencesForCRLBinaries(crlBinaries));

        List<OCSPResponseBinary> ocspBinaries = getEncapsulatedOCSPBinaries(cryptographicInformationList);
        addReferences(references, createReferencesForOCSPBinaries(ocspBinaries, certificateSource));

        return references;
    }

    private List<CertificateToken> getEncapsulatedCertificateTokens(List<CryptographicInformation> cryptographicInformationList) {
        final List<CertificateToken> certificateTokens = new ArrayList<>();
        for (CryptographicInformation cryptographicInformation : cryptographicInformationList) {
            if (CryptographicInformationType.CERT == cryptographicInformation.getType()) {
                try {
                    CertificateToken certificateToken = DSSUtils.loadCertificate(cryptographicInformation.getContent());
                    certificateTokens.add(certificateToken);
                } catch (Exception e) {
                    String errorMessage = "Unable to parse an encapsulated certificate : {}";
                    if (LOG.isDebugEnabled()) {
                        LOG.warn(errorMessage, e.getMessage(), e);
                    } else {
                        LOG.warn(errorMessage, e.getMessage());
                    }
                }
            }
        }
        return certificateTokens;
    }

    private List<CRLBinary> getEncapsulatedCRLBinaries(List<CryptographicInformation> cryptographicInformationList) {
        final List<CRLBinary> crlBinaries = new ArrayList<>();
        for (CryptographicInformation cryptographicInformation : cryptographicInformationList) {
            if (CryptographicInformationType.CRL == cryptographicInformation.getType()) {
                try {
                    CRLBinary crlBinary = CRLUtils.buildCRLBinary(cryptographicInformation.getContent());
                    crlBinaries.add(crlBinary);
                } catch (Exception e) {
                    String errorMessage = "Unable to parse an encapsulated CRL : {}";
                    if (LOG.isDebugEnabled()) {
                        LOG.warn(errorMessage, e.getMessage(), e);
                    } else {
                        LOG.warn(errorMessage, e.getMessage());
                    }
                }
            }
        }
        return crlBinaries;
    }

    private List<OCSPResponseBinary> getEncapsulatedOCSPBinaries(List<CryptographicInformation> cryptographicInformationList) {
        final List<OCSPResponseBinary> ocspBinaries = new ArrayList<>();
        for (CryptographicInformation cryptographicInformation : cryptographicInformationList) {
            if (CryptographicInformationType.OCSP == cryptographicInformation.getType()) {
                try {
                    BasicOCSPResp basicOCSPResp = DSSRevocationUtils.loadOCSPFromBinaries(cryptographicInformation.getContent());
                    OCSPResponseBinary ocspResponseBinary = OCSPResponseBinary.build(basicOCSPResp);
                    ocspBinaries.add(ocspResponseBinary);
                } catch (Exception e) {
                    String errorMessage = "Unable to parse an encapsulated OCSP : {}";
                    if (LOG.isDebugEnabled()) {
                        LOG.warn(errorMessage, e.getMessage(), e);
                    } else {
                        LOG.warn(errorMessage, e.getMessage());
                    }
                }
            }
        }
        return ocspBinaries;
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

    /**
     * Allows to populate all sources from an external evidence record
     *
     * @param externalEvidenceRecord {@link EvidenceRecord} to populate data from
     */
    protected void populateSources(EvidenceRecord externalEvidenceRecord) {
        if (externalEvidenceRecord != null) {
            certificateSource.add(externalEvidenceRecord.getCertificateSource());
            crlSource.add(externalEvidenceRecord.getCRLSource());
            ocspSource.add(externalEvidenceRecord.getOCSPSource());
            for (TimestampToken timestampToken : externalEvidenceRecord.getTimestamps()) {
                populateSources(timestampToken);
            }
        }
    }

}
