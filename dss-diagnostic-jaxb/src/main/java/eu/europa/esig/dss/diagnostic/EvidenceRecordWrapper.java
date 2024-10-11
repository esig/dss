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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.EvidenceRecordOrigin;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Provides a user-friendly interface for dealing with JAXB {@code eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord} object
 *
 */
public class EvidenceRecordWrapper {

    /** Wrapped XML Evidence Record object */
    private final XmlEvidenceRecord evidenceRecord;

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link XmlEvidenceRecord}
     */
    public EvidenceRecordWrapper(final XmlEvidenceRecord evidenceRecord) {
        Objects.requireNonNull(evidenceRecord, "XmlEvidenceRecord cannot be null!");
        this.evidenceRecord = evidenceRecord;
    }

    /**
     * Gets unique identifier
     *
     * @return {@link String}
     */
    public String getId() {
        return evidenceRecord.getId();
    }

    /**
     * Checks if the evidence record's Id is duplicated within the validating document
     *
     * @return TRUE if there is a duplicated evidence record Id, FALSE otherwise
     */
    public boolean isEvidenceRecordDuplicated() {
        return evidenceRecord.isDuplicated() != null && evidenceRecord.isDuplicated();
    }

    /**
     * Returns name of the evidence record's document, when applicable
     *
     * @return {@link String}
     */
    public String getFilename() {
        return evidenceRecord.getDocumentName();
    }

    /**
     * Gets a list of digest matchers representing the associated archival data objects validation status
     *
     * @return a list of {@link XmlDigestMatcher}
     */
    public List<XmlDigestMatcher> getDigestMatchers() {
        return evidenceRecord.getDigestMatchers();
    }

    /**
     * Returns initial time-stamp of the evidence record
     *
     * @return {@link TimestampWrapper}
     */
    public TimestampWrapper getFirstTimestamp() {
        List<TimestampWrapper> timestampList = getTimestampList();
        if (timestampList != null && timestampList.size() > 0) {
            return timestampList.get(0);
        }
        return null;
    }

    /**
     * Gets a list of time-stamp tokens associated with the evidence record
     *
     * @return a list of {@link TimestampWrapper}s
     */
    public List<TimestampWrapper> getTimestampList() {
        List<TimestampWrapper> tsps = new ArrayList<>();
        List<XmlFoundTimestamp> timestamps = evidenceRecord.getEvidenceRecordTimestamps();
        for (XmlFoundTimestamp xmlFoundTimestamp : timestamps) {
            tsps.add(new TimestampWrapper(xmlFoundTimestamp.getTimestamp()));
        }
        return tsps;
    }

    /**
     * Returns a list of time-stamp identifiers associated with the Evidence Record
     *
     * @return a list of {@link String}s
     */
    public List<String> getTimestampIdsList() {
        List<String> result = new ArrayList<>();
        List<TimestampWrapper> timestamps = getTimestampList();
        if (timestamps != null) {
            for (TimestampWrapper tsp : timestamps) {
                result.add(tsp.getId());
            }
        }
        return result;
    }

    /**
     * Returns a collection of certificate tokens embedded within Evidence Record
     *
     * @return {@link FoundCertificatesProxy}
     */
    public FoundCertificatesProxy foundCertificates() {
        return new FoundCertificatesProxy(evidenceRecord.getFoundCertificates());
    }

    /**
     * Returns a collection of revocation tokens embedded within Evidence Record
     *
     * @return {@link FoundRevocationsProxy}
     */
    public FoundRevocationsProxy foundRevocations() {
        return new FoundRevocationsProxy(evidenceRecord.getFoundRevocations());
    }

    /**
     * Gets the evidence record format type
     *
     * @return {@link EvidenceRecordTypeEnum}
     */
    public EvidenceRecordTypeEnum getEvidenceRecordType() {
        return evidenceRecord.getType();
    }

    /**
     * Gets the origin of the evidence record
     *
     * @return {@link EvidenceRecordOrigin}
     */
    public EvidenceRecordOrigin getOrigin() {
        return evidenceRecord.getOrigin();
    }

    /**
     * Gets if a structural validation of the evidence record is valid
     *
     * @return TRUE if the structure of the evidence record is valid, FALSE otherwise
     */
    public boolean isStructuralValidationValid() {
        return evidenceRecord.getStructuralValidation() != null && evidenceRecord.getStructuralValidation().isValid();
    }

    /**
     * Returns structural validation error messages, when applicable
     *
     * @return a list of {@link String} error messages
     */
    public List<String> getStructuralValidationMessages() {
        XmlStructuralValidation structuralValidation = evidenceRecord.getStructuralValidation();
        if (structuralValidation != null) {
            return structuralValidation.getMessages();
        }
        return Collections.emptyList();
    }

    /**
     * Returns a list of objects covered by the evidence record
     *
     * @return a list of {@link XmlTimestampedObject}s
     */
    public List<XmlTimestampedObject> getCoveredObjects() {
        return evidenceRecord.getTimestampedObjects();
    }

    /**
     * Returns a list of {@link SignatureWrapper}s covered be the current evidence record
     *
     * @return list of {@link SignatureWrapper}s
     */
    public List<SignatureWrapper> getCoveredSignatures() {
        List<SignatureWrapper> signatures = new ArrayList<>();

        List<XmlAbstractToken> coveredObjectsByCategory = getCoveredObjectsByCategory(TimestampedObjectType.SIGNATURE);
        for (XmlAbstractToken token : coveredObjectsByCategory) {
            if (token instanceof XmlSignature) {
                signatures.add(new SignatureWrapper((XmlSignature) token));
            } else {
                throw new IllegalArgumentException(
                        String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.SIGNATURE));
            }
        }
        return signatures;
    }

    /**
     * Returns a list of certificates covered be the current evidence record
     *
     * @return list of {@link CertificateWrapper}s
     */
    public List<CertificateWrapper> getCoveredCertificates() {
        List<CertificateWrapper> certificates = new ArrayList<>();

        List<XmlAbstractToken> coveredObjectsByCategory = getCoveredObjectsByCategory(TimestampedObjectType.CERTIFICATE);
        for (XmlAbstractToken token : coveredObjectsByCategory) {
            if (token instanceof XmlCertificate) {
                certificates.add(new CertificateWrapper((XmlCertificate) token));
            } else {
                throw new IllegalArgumentException(
                        String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.CERTIFICATE));
            }
        }
        return certificates;
    }

    /**
     * Returns a list of revocation data covered be the current evidence record
     *
     * @return list of {@link RevocationWrapper}s
     */
    public List<RevocationWrapper> getCoveredRevocations() {
        List<RevocationWrapper> revocations = new ArrayList<>();

        List<XmlAbstractToken> coveredObjectsByCategory = getCoveredObjectsByCategory(TimestampedObjectType.REVOCATION);
        for (XmlAbstractToken token : coveredObjectsByCategory) {
            if (token instanceof XmlRevocation) {
                revocations.add(new RevocationWrapper((XmlRevocation) token));
            } else {
                throw new IllegalArgumentException(
                        String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.REVOCATION));
            }
        }
        return revocations;
    }

    /**
     * Returns a list of timestamps covered be the current evidence record
     *
     * @return list of {@link TimestampWrapper}s
     */
    public List<TimestampWrapper> getCoveredTimestamps() {
        List<TimestampWrapper> timestamps = new ArrayList<>();

        List<XmlAbstractToken> coveredObjectsByCategory = getCoveredObjectsByCategory(TimestampedObjectType.TIMESTAMP);
        for (XmlAbstractToken token : coveredObjectsByCategory) {
            if (token instanceof XmlTimestamp) {
                timestamps.add(new TimestampWrapper((XmlTimestamp) token));
            } else {
                throw new IllegalArgumentException(
                        String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.TIMESTAMP));
            }
        }
        return timestamps;
    }

    /**
     * Returns a list of evidence records covered be the current evidence record
     *
     * @return list of {@link EvidenceRecordWrapper}s
     */
    public List<EvidenceRecordWrapper> getCoveredEvidenceRecords() {
        List<EvidenceRecordWrapper> evidenceRecords = new ArrayList<>();

        List<XmlAbstractToken> coveredObjectsByCategory = getCoveredObjectsByCategory(TimestampedObjectType.EVIDENCE_RECORD);
        for (XmlAbstractToken token : coveredObjectsByCategory) {
            if (token instanceof XmlEvidenceRecord) {
                evidenceRecords.add(new EvidenceRecordWrapper((XmlEvidenceRecord) token));
            } else {
                throw new IllegalArgumentException(
                        String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.EVIDENCE_RECORD));
            }
        }
        return evidenceRecords;
    }

    /**
     * Returns a list of Signed data covered be the current evidence record
     *
     * @return list of {@link SignerDataWrapper}s
     */
    public List<SignerDataWrapper> getCoveredSignedData() {
        List<SignerDataWrapper> timestamps = new ArrayList<>();

        List<XmlAbstractToken> coveredObjectsByCategory = getCoveredObjectsByCategory(TimestampedObjectType.SIGNED_DATA);
        for (XmlAbstractToken token : coveredObjectsByCategory) {
            if (token instanceof XmlSignerData) {
                timestamps.add(new SignerDataWrapper((XmlSignerData) token));
            } else {
                throw new IllegalArgumentException(
                        String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.SIGNED_DATA));
            }
        }
        return timestamps;
    }

    /**
     * Returns a list of all OrphanTokens covered by the evidence record
     *
     * @return list of {@link OrphanTokenWrapper}s
     */
    @SuppressWarnings("rawtypes")
    public List<OrphanTokenWrapper> getAllCoveredOrphanTokens() {
        List<OrphanTokenWrapper> timestampedObjectIds = new ArrayList<>();
        timestampedObjectIds.addAll(getCoveredOrphanCertificates());
        timestampedObjectIds.addAll(getCoveredOrphanRevocations());
        return timestampedObjectIds;
    }

    /**
     * Returns a list of OrphanCertificateTokens covered by the evidence record
     *
     * @return list of orphan certificates
     */
    public List<OrphanCertificateTokenWrapper> getCoveredOrphanCertificates() {
        List<OrphanCertificateTokenWrapper> orphanCertificates = new ArrayList<>();

        List<XmlAbstractToken> coveredObjectsByCategory = getCoveredObjectsByCategory(TimestampedObjectType.ORPHAN_CERTIFICATE);
        for (XmlAbstractToken token : coveredObjectsByCategory) {
            if (token instanceof XmlOrphanCertificateToken) {
                orphanCertificates.add(new OrphanCertificateTokenWrapper((XmlOrphanCertificateToken) token));
            } else {
                throw new IllegalArgumentException(
                        String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.ORPHAN_CERTIFICATE));
            }
        }
        return orphanCertificates;
    }

    /**
     * Returns a list of OrphanRevocationTokens covered by the evidence record
     *
     * @return list of orphan revocations
     */
    public List<OrphanRevocationTokenWrapper> getCoveredOrphanRevocations() {
        List<OrphanRevocationTokenWrapper> orphanRevocations = new ArrayList<>();

        List<XmlAbstractToken> coveredObjectsByCategory = getCoveredObjectsByCategory(TimestampedObjectType.ORPHAN_REVOCATION);
        for (XmlAbstractToken token : coveredObjectsByCategory) {
            if (token instanceof XmlOrphanRevocationToken) {
                orphanRevocations.add(new OrphanRevocationTokenWrapper((XmlOrphanRevocationToken) token));
            } else {
                throw new IllegalArgumentException(
                        String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.ORPHAN_REVOCATION));
            }
        }
        return orphanRevocations;
    }

    private List<XmlAbstractToken> getCoveredObjectsByCategory(TimestampedObjectType category) {
        List<XmlAbstractToken> coveredObjectIds = new ArrayList<>();
        for (XmlTimestampedObject coveredObject : getCoveredObjects()) {
            if (category == coveredObject.getCategory()) {
                coveredObjectIds.add(coveredObject.getToken());
            }
        }
        return coveredObjectIds;
    }

    /**
     * Returns Evidence record's Signature Scopes
     *
     * @return a list of {@link XmlSignatureScope}s
     */
    public List<XmlSignatureScope> getEvidenceRecordScopes() {
        return evidenceRecord.getEvidenceRecordScopes();
    }

    /**
     * Returns binaries of the evidence record
     *
     * @return byet array
     */
    public byte[] getBinaries() {
        return evidenceRecord.getBase64Encoded();
    }

    /**
     * Returns digest algorithm and value of the timestamp token binaries, when defined
     *
     * @return {@link XmlDigestAlgoAndValue}
     */
    public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
        return evidenceRecord.getDigestAlgoAndValue();
    }

}
