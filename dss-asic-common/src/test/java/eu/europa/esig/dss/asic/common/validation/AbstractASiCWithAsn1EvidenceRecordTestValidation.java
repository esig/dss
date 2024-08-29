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
package eu.europa.esig.dss.asic.common.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractASiCWithAsn1EvidenceRecordTestValidation extends AbstractASiCWithEvidenceRecordTestValidation {

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertTrue(Utils.isCollectionNotEmpty(detachedEvidenceRecords));

        for (EvidenceRecord evidenceRecord : detachedEvidenceRecords) {
            List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
            for (ReferenceValidation referenceValidation : referenceValidationList) {
                if (allArchiveDataObjectsProvidedToValidation() ||
                        DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != referenceValidation.getType()) {
                    assertTrue(referenceValidation.isFound());
                    assertTrue(referenceValidation.isIntact());
                }
            }

            List<TimestampedReference> timestampedReferences = evidenceRecord.getTimestampedReferences();
            assertTrue(Utils.isCollectionNotEmpty(timestampedReferences));

            ManifestFile manifestFile = evidenceRecord.getManifestFile();
            int tstCounter = 0;

            List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
            for (TimestampToken timestampToken : timestamps) {
                assertTrue(timestampToken.isProcessed());
                assertTrue(timestampToken.isMessageImprintDataFound());
                assertTrue(timestampToken.isMessageImprintDataIntact());

                if (tstCounter > 0) {
                    List<ReferenceValidation> tstReferenceValidationList = timestampToken.getReferenceValidations();
                    assertTrue(Utils.isCollectionNotEmpty(tstReferenceValidationList));

                    boolean archiveTstDigestFound = false;
                    boolean archiveTstSequenceDigestFound = false;
                    for (ReferenceValidation referenceValidation : tstReferenceValidationList) {
                        if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(referenceValidation.getType())) {
                            archiveTstDigestFound = true;
                        } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT.equals(referenceValidation.getType())) {
                            archiveTstSequenceDigestFound = true;
                        } else if (allArchiveDataObjectsProvidedToValidation() ||
                                DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != referenceValidation.getType()) {
                            assertTrue(referenceValidation.isFound());
                            assertTrue(referenceValidation.isIntact());
                        }
                    }

                    if (manifestFile == null || manifestFile.getEntries().size() != 1) {
                        if (tstReferenceValidationList.size() == 1) {
                            assertTrue(archiveTstDigestFound);
                        } else {
                            assertTrue(archiveTstSequenceDigestFound);
                        }
                    }

                }

                ++tstCounter;
            }
        }
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();
        List<String> contentFiles = containerInfo.getContentFiles();
        List<XmlManifestFile> manifestFiles = containerInfo.getManifestFiles();

        for (EvidenceRecordWrapper evidenceRecord : diagnosticData.getEvidenceRecords()) {

            int tstCounter = 0;
            XmlManifestFile xmlManifestFile = getRelatedXmlManifestFile(manifestFiles, evidenceRecord);

            List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
            for (TimestampWrapper timestamp : timestamps) {
                assertTrue(timestamp.isMessageImprintDataFound());
                assertTrue(timestamp.isMessageImprintDataIntact());
                assertTrue(timestamp.isSignatureIntact());
                assertTrue(timestamp.isSignatureValid());

                List<XmlSignatureScope> timestampScopes = timestamp.getTimestampScopes();
                if (xmlManifestFile != null) {
                    assertEquals(xmlManifestFile.getEntries().size(), timestampScopes.size());
                } else {
                    assertEquals(contentFiles.size(), timestampScopes.size());
                }

                List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
                assertTrue(Utils.isCollectionNotEmpty(timestampedObjects));

                if (tstCounter > 0) {
                    List<XmlDigestMatcher> tstDigestMatcherList = timestamp.getDigestMatchers();
                    assertTrue(Utils.isCollectionNotEmpty(tstDigestMatcherList));

                    boolean archiveTstDigestFound = false;
                    for (XmlDigestMatcher digestMatcher : tstDigestMatcherList) {
                        if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(digestMatcher.getType())) {
                            archiveTstDigestFound = true;
                        } else if ((allArchiveDataObjectsProvidedToValidation() && tstCoversOnlyCurrentHashTreeData()) ||
                                DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE != digestMatcher.getType()) {
                            assertTrue(digestMatcher.isDataFound());
                            assertTrue(digestMatcher.isDataFound());
                        }
                    }

                    if (tstDigestMatcherList.size() == 2 && (xmlManifestFile == null || xmlManifestFile.getEntries().size() != 1)) {
                        assertTrue(archiveTstDigestFound || !tstCoversOnlyCurrentHashTreeData());
                    }
                }

                ++tstCounter;
            }
        }
    }

    private XmlManifestFile getRelatedXmlManifestFile(List<XmlManifestFile> manifestFiles, EvidenceRecordWrapper evidenceRecordWrapper) {
        if (Utils.isCollectionEmpty(manifestFiles)) {
            return null;
        }
        for (XmlManifestFile xmlManifestFile : manifestFiles) {
            if (evidenceRecordWrapper.getFilename().equals(xmlManifestFile.getSignatureFilename())) {
                return xmlManifestFile;
            }
        }
        return null;
    }

}
