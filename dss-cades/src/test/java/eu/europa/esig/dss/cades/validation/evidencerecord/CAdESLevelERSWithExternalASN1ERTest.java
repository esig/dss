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
package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.EvidenceRecordOrigin;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelERSWithExternalASN1ERTest extends AbstractCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESLevelBWithEmbeddedEvidenceRecordTest.class.getResourceAsStream("/validation/evidence-record/C-E-ERS.p7m"));
    }

    @Override
    protected List<DSSDocument> getDetachedEvidenceRecords() {
        return Collections.singletonList(new InMemoryDocument(
                CAdESLevelBWithEmbeddedEvidenceRecordTest.class.getResourceAsStream("/validation/evidence-record/evidence-record-C-E-ERS.ers")));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_ERS, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
        assertEquals(2, evidenceRecords.size());

        boolean signatureERFound = false;
        boolean externalERFound = false;
        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            if (EvidenceRecordOrigin.SIGNATURE == evidenceRecord.getOrigin()) {
                assertEquals(EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD, evidenceRecord.getEvidenceRecordType());
                assertEquals(EvidenceRecordIncorporationType.INTERNAL_EVIDENCE_RECORD, evidenceRecord.getIncorporationType());

                boolean coversSignature = false;
                boolean coversSignedData = false;
                boolean coversCertificates = false;
                boolean coversRevocationData = false;
                boolean coversTimestamps = false;
                boolean coversEvidenceRecords = false;
                List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
                assertTrue(Utils.isCollectionNotEmpty(coveredObjects));
                for (XmlTimestampedObject reference : coveredObjects) {
                    if (TimestampedObjectType.SIGNATURE == reference.getCategory()) {
                        coversSignature = true;
                    } else if (TimestampedObjectType.SIGNED_DATA == reference.getCategory()) {
                        coversSignedData = true;
                    } else if (TimestampedObjectType.CERTIFICATE == reference.getCategory()) {
                        coversCertificates = true;
                    } else if (TimestampedObjectType.REVOCATION == reference.getCategory()) {
                        coversRevocationData = true;
                    } else if (TimestampedObjectType.TIMESTAMP == reference.getCategory()) {
                        coversTimestamps = true;
                    } else if (TimestampedObjectType.EVIDENCE_RECORD == reference.getCategory()) {
                        coversEvidenceRecords = true;
                    }
                }
                assertTrue(coversSignature);
                assertTrue(coversSignedData);
                assertTrue(coversCertificates);
                assertTrue(coversTimestamps);
                assertTrue(coversRevocationData);
                assertFalse(coversEvidenceRecords);

                List<XmlSignatureScope> evidenceRecordScopes = evidenceRecord.getEvidenceRecordScopes();
                assertEquals(2, evidenceRecordScopes.size());

                boolean fullDocFound = false;
                boolean sigFound = false;
                for (XmlSignatureScope signatureScope : evidenceRecordScopes) {
                    if (SignatureScopeType.FULL == signatureScope.getScope()) {
                        fullDocFound = true;
                    } else if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                        sigFound = true;
                    }
                }
                assertTrue(fullDocFound);
                assertTrue(sigFound);

                signatureERFound = true;

            } else if (EvidenceRecordOrigin.EXTERNAL == evidenceRecord.getOrigin()) {
                assertEquals(EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD, evidenceRecord.getEvidenceRecordType());
                assertNull(evidenceRecord.getIncorporationType());

                boolean coversSignature = false;
                boolean coversSignedData = false;
                boolean coversCertificates = false;
                boolean coversRevocationData = false;
                boolean coversTimestamps = false;
                boolean coversEvidenceRecords = false;
                List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
                assertTrue(Utils.isCollectionNotEmpty(coveredObjects));
                for (XmlTimestampedObject reference : coveredObjects) {
                    if (TimestampedObjectType.SIGNATURE == reference.getCategory()) {
                        coversSignature = true;
                    } else if (TimestampedObjectType.SIGNED_DATA == reference.getCategory()) {
                        coversSignedData = true;
                    } else if (TimestampedObjectType.CERTIFICATE == reference.getCategory()) {
                        coversCertificates = true;
                    } else if (TimestampedObjectType.REVOCATION == reference.getCategory()) {
                        coversRevocationData = true;
                    } else if (TimestampedObjectType.TIMESTAMP == reference.getCategory()) {
                        coversTimestamps = true;
                    } else if (TimestampedObjectType.EVIDENCE_RECORD == reference.getCategory()) {
                        coversEvidenceRecords = true;
                    }
                }
                assertTrue(coversSignature);
                assertTrue(coversSignedData);
                assertTrue(coversCertificates);
                assertTrue(coversTimestamps);
                assertTrue(coversRevocationData);
                assertTrue(coversEvidenceRecords);

                List<XmlSignatureScope> evidenceRecordScopes = evidenceRecord.getEvidenceRecordScopes();
                assertEquals(1, evidenceRecordScopes.size());

                boolean fullDocFound = false;
                boolean sigFound = false;
                for (XmlSignatureScope signatureScope : evidenceRecordScopes) {
                    if (SignatureScopeType.FULL == signatureScope.getScope()) {
                        fullDocFound = true;
                    } else if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                        sigFound = true;
                    }
                }
                assertTrue(fullDocFound);
                assertFalse(sigFound);

                externalERFound = true;
            }
        }
        assertTrue(signatureERFound);
        assertTrue(externalERFound);
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(2, evidenceRecords.size());

        for (EvidenceRecordWrapper evidenceRecordWrapper : evidenceRecords) {
            List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
            assertEquals(1, timestampList.size());

            TimestampWrapper timestampWrapper = timestampList.get(0);
            assertNotNull(timestampWrapper.getProductionTime());
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());

            assertTrue(timestampWrapper.isSigningCertificateIdentified());
            assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
            assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());
        }
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
        assertEquals(2, signatureEvidenceRecords.size());

        boolean signatureERFound = false;
        boolean externalERFound = false;
        for (XmlEvidenceRecord evidenceRecord : signatureEvidenceRecords) {
            assertEquals(Indication.INDETERMINATE, evidenceRecord.getIndication());
            assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, evidenceRecord.getSubIndication());

            for (XmlTimestamp timestamp : evidenceRecord.getTimestamps().getTimestamp()) {
                assertEquals(Indication.INDETERMINATE, timestamp.getIndication());
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, timestamp.getSubIndication());
            }

            if (Utils.collectionSize(evidenceRecord.getEvidenceRecordScope()) == 1) {
                externalERFound = true;
            } else if (Utils.collectionSize(evidenceRecord.getEvidenceRecordScope()) == 2) {
                signatureERFound = true;
            }
        }
        assertTrue(signatureERFound);
        assertTrue(externalERFound);
    }

}
