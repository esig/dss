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
package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XmlEvidenceRecordWithValidationDataTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-simple-validation-data.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "dCeyHarzzN3cWzVNTMKZyY00rW4gNGGto/2ZLfzpsXM="));
    }

    @Override
    protected void checkEvidenceRecordValidationData(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordValidationData(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        FoundCertificatesProxy foundCertificates = evidenceRecordWrapper.foundCertificates();
        assertEquals(2, Utils.collectionSize(foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.EVIDENCE_RECORD)));
        assertEquals(0, Utils.collectionSize(foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.EVIDENCE_RECORD)));
        assertEquals(0, Utils.collectionSize(foundCertificates.getRelatedCertificateRefs()));
        assertEquals(0, Utils.collectionSize(foundCertificates.getOrphanCertificateRefs()));

        FoundRevocationsProxy foundRevocations = evidenceRecordWrapper.foundRevocations();
        assertEquals(1, Utils.collectionSize(foundRevocations.getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.EVIDENCE_RECORD)));
        assertEquals(0, Utils.collectionSize(foundRevocations.getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.EVIDENCE_RECORD)));
        assertEquals(0, Utils.collectionSize(foundRevocations.getOrphanRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.EVIDENCE_RECORD)));
        assertEquals(1, Utils.collectionSize(foundRevocations.getOrphanRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.EVIDENCE_RECORD)));
        assertEquals(0, Utils.collectionSize(foundRevocations.getRelatedRevocationRefs()));
        assertEquals(0, Utils.collectionSize(foundRevocations.getOrphanRevocationRefs()));
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertEquals(1, Utils.collectionSize(diagnosticData.getAllOrphanCertificateObjects())); // cert is coming from orphan OCSP
        assertEquals(1, Utils.collectionSize(diagnosticData.getAllOrphanRevocationObjects()));
    }

}
