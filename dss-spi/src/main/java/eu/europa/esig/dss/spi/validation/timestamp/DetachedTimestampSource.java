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
package eu.europa.esig.dss.spi.validation.timestamp;

import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ListRevocationSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.ArrayList;
import java.util.List;

/**
 * Performs processing of detached timestamps
 */
public class DetachedTimestampSource extends AbstractTimestampSource {

    /** Merged certificate source from timestamps */
    private final ListCertificateSource certificateSource = new ListCertificateSource();

    /** Merged CRL source */
    private final ListRevocationSource<CRL> crlSource = new ListRevocationSource<>();

    /** Merged OCSP source */
    private final ListRevocationSource<OCSP> ocspSource = new ListRevocationSource<>();

    /** A list of detached timestamps */
    private final List<TimestampToken> detachedTimestamps = new ArrayList<>();

    /** This variable contains the list of evidence records detached from the time-stamp document. */
    private final List<EvidenceRecord> detachedEvidenceRecords = new ArrayList<>();

    /**
     * Default constructor instantiating object with empty resources
     */
    public DetachedTimestampSource() {
        // empty
    }

    /**
     * Constructor to instantiate a list of time-stamps with the given {@code TimestampToken}
     *
     * @param timestampToken {@link TimestampToken}
     */
    public DetachedTimestampSource(TimestampToken timestampToken) {
        this.detachedTimestamps.add(timestampToken);
    }

    /**
     * Returns a list of processed detached timestamps
     *
     * @return a list of {@link TimestampToken}s
     */
    public List<TimestampToken> getDetachedTimestamps() {
        return detachedTimestamps;
    }

    /**
     * Adds the external timestamp to the source
     *
     * @param timestamp {@link TimestampToken}
     */
    public void addExternalTimestamp(TimestampToken timestamp) {
        processExternalTimestamp(timestamp);
        detachedTimestamps.add(timestamp);
    }

    private void processExternalTimestamp(TimestampToken externalTimestamp) {
        populateSources(externalTimestamp);
        addReferences(externalTimestamp.getTimestampedReferences(), getManifestReferences(externalTimestamp));
    }

    private List<TimestampedReference> getManifestReferences(TimestampToken externalTimestamp) {
        List<TimestampedReference> result = new ArrayList<>();
        ManifestFile manifestFile = externalTimestamp.getManifestFile();
        if (manifestFile != null) {
            for (TimestampToken timestampToken : detachedTimestamps) {
                if (manifestFile.isDocumentCovered(timestampToken.getFileName())) {
                    addReferences(result,
                            getReferencesFromTimestamp(timestampToken, certificateSource, crlSource, ocspSource));
                }
            }
        }
        return result;
    }

    /**
     * Adds the external evidence record to the source
     *
     * @param evidenceRecord {@link EvidenceRecord}
     */
    public void addExternalEvidenceRecord(EvidenceRecord evidenceRecord) {
        processExternalEvidenceRecord(evidenceRecord);
        detachedEvidenceRecords.add(evidenceRecord);
    }

    private void processExternalEvidenceRecord(EvidenceRecord evidenceRecord) {
        addEncapsulatedReferencesFromTimestamps(evidenceRecord, getDetachedTimestamps());
        processEvidenceRecordTimestamps(evidenceRecord);
        processEmbeddedEvidenceRecords(evidenceRecord);
        for (TimestampToken timestampToken : evidenceRecord.getTimestamps()) {
            populateSources(timestampToken);
        }
    }

    private void populateSources(TimestampToken timestampToken) {
        certificateSource.add(timestampToken.getCertificateSource());
        crlSource.add(timestampToken.getCRLSource());
        ocspSource.add(timestampToken.getOCSPSource());
    }

    private void addEncapsulatedReferencesFromTimestamps(EvidenceRecord evidenceRecord, List<TimestampToken> timestampTokens) {
        for (TimestampToken timestampToken : timestampTokens) {
            if (isCoveredTimestamp(evidenceRecord, timestampToken)) {
                addReferences(evidenceRecord.getTimestampedReferences(),
                        getReferencesFromTimestamp(timestampToken, certificateSource, crlSource, ocspSource));
            }
        }
    }

    private boolean isCoveredTimestamp(EvidenceRecord evidenceRecord, TimestampToken timestampToken) {
        ManifestFile manifestFile = evidenceRecord.getManifestFile();
        if (manifestFile != null) {
            for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
                if (timestampToken.getFileName() != null && timestampToken.getFileName().equals(manifestEntry.getFileName())) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

}
