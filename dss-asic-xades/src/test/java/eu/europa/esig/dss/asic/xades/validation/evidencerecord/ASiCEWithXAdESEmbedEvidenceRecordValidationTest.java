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
package eu.europa.esig.dss.asic.xades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.asic.xades.signature.DefaultASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.evidencerecord.xml.digest.XMLEvidenceRecordDataObjectDigestBuilderFactory;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithXAdESEmbedEvidenceRecordValidationTest extends AbstractASiCWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        DSSDocument originalZip = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.sce");

        ASiCContainerExtractor containerExtractor = DefaultASiCContainerExtractor.fromDocument(originalZip);
        ASiCContent asicContent = containerExtractor.extract();

        DSSDocument erDocument = createERDocument(asicContent);
        DSSDocument erManifestDocument = createERManifestDocument(asicContent, erDocument);

        asicContent.setEvidenceRecordDocuments(Collections.singletonList(erDocument));
        asicContent.setEvidenceRecordManifestDocuments(Collections.singletonList(erManifestDocument));

        return ZipUtils.getInstance().createZipArchive(asicContent);
    }

    private DSSDocument createERDocument(ASiCContent asicContent) {
        // this method is used to simulate creation of ER document
        // for test purposes, the method does not create an ER, but only validates the original ER
        List<DSSDocument> evidenceRecordDocuments = asicContent.getEvidenceRecordDocuments();

        ASiCEvidenceRecordDigestBuilder asicERDigestBuilder = new ASiCEvidenceRecordDigestBuilder(asicContent, DigestAlgorithm.SHA256);
        asicERDigestBuilder.setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter());
        asicERDigestBuilder.setDataObjectDigestBuilderFactory(new XMLEvidenceRecordDataObjectDigestBuilderFactory());

        List<DSSDocument> detachedContents = new ArrayList<>();
        for (Digest digest : asicERDigestBuilder.buildDigestGroup()) {
            detachedContents.add(new DigestDocument(digest.getAlgorithm(), Utils.toBase64(digest.getValue()), UUID.randomUUID().toString()));
        }

        DSSDocument erDocument = evidenceRecordDocuments.get(0);
        EvidenceRecordAnalyzer evidenceRecordAnalyzer = DefaultEvidenceRecordAnalyzer.fromDocument(erDocument);
        evidenceRecordAnalyzer.setCertificateVerifier(getOfflineCertificateVerifier());
        evidenceRecordAnalyzer.setDetachedContents(detachedContents);

        ValidationContext validationContext = evidenceRecordAnalyzer.validate();
        Set<EvidenceRecord> evidenceRecords = validationContext.getProcessedEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecord evidenceRecord = evidenceRecords.iterator().next();
        assertEquals(2, evidenceRecord.getReferenceValidation().size());
        for (ReferenceValidation referenceValidation : evidenceRecord.getReferenceValidation()) {
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        assertEquals(1, timestamps.size());

        TimestampToken timestampToken = timestamps.get(0);
        assertTrue(timestampToken.isMessageImprintDataFound());
        assertTrue(timestampToken.isMessageImprintDataIntact());
        assertTrue(timestampToken.isSignatureIntact());
        assertTrue(timestampToken.isValid());

        // remove original ER
        asicContent.setEvidenceRecordDocuments(null);

        // set filename
        DefaultASiCWithXAdESFilenameFactory filenameFactory = new DefaultASiCWithXAdESFilenameFactory();
        String erFilename = filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD);
        erDocument.setName(erFilename);

        // return the ER
        return erDocument;
    }

    private DSSDocument createERManifestDocument(ASiCContent asicContent, DSSDocument erDocument) {
        asicContent.setEvidenceRecordManifestDocuments(null);

        ASiCEvidenceRecordManifestBuilder manifestBuilder = new ASiCEvidenceRecordManifestBuilder(asicContent,
                DigestAlgorithm.SHA256, erDocument.getName())
                .setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter())
                .setEvidenceRecordFilenameFactory(new DefaultASiCWithXAdESFilenameFactory());
        return manifestBuilder.build();
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordDigestMatchers(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        List<XmlDigestMatcher> digestMatchers = evidenceRecords.get(0).getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        boolean zipFileFound = false;
        boolean txtFileFound = false;
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, digestMatcher.getType());
            assertNotNull(digestMatcher.getDigestMethod());
            assertNotNull(digestMatcher.getDigestValue());
            assertTrue(digestMatcher.isDataFound());
            assertTrue(digestMatcher.isDataIntact());
            if ("test.zip".equals(digestMatcher.getName())) {
                zipFileFound = true;
            } else if ("test.txt".equals(digestMatcher.getName())) {
                txtFileFound = true;
            }
        }
        assertTrue(zipFileFound);
        assertTrue(txtFileFound);
    }

}
