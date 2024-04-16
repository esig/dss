package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.asic.cades.DefaultASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithAsn1EvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilderFactory;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithCAdESEmbedEvidenceRecordValidationTest extends AbstractASiCWithAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        DSSDocument originalZip =  new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-multi-files.asice");

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
        asicERDigestBuilder.setDataObjectDigestBuilderFactory(new ASN1EvidenceRecordDataObjectDigestBuilderFactory());

        List<DSSDocument> detachedContents = new ArrayList<>();
        for (Digest digest : asicERDigestBuilder.buildDigestGroup()) {
            detachedContents.add(new DigestDocument(digest.getAlgorithm(), Utils.toBase64(digest.getValue()), UUID.randomUUID().toString()));
        }

        DSSDocument erDocument = evidenceRecordDocuments.get(0);
        EvidenceRecordValidator erValidator = EvidenceRecordValidator.fromDocument(erDocument);
        erValidator.setCertificateVerifier(getOfflineCertificateVerifier());
        erValidator.setDetachedContents(detachedContents);

        Reports reports = erValidator.validateDocument();
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        assertEquals(2, evidenceRecords.get(0).getDigestMatchers().size());
        for (XmlDigestMatcher digestMatcher : evidenceRecords.get(0).getDigestMatchers()) {
            assertTrue(digestMatcher.isDataFound());
            assertTrue(digestMatcher.isDataIntact());
        }

        assertEquals(1, evidenceRecords.get(0).getTimestampList().size());
        assertTrue(evidenceRecords.get(0).getTimestampList().get(0).isMessageImprintDataFound());
        assertTrue(evidenceRecords.get(0).getTimestampList().get(0).isMessageImprintDataIntact());
        assertTrue(evidenceRecords.get(0).getTimestampList().get(0).isSignatureIntact());
        assertTrue(evidenceRecords.get(0).getTimestampList().get(0).isSignatureValid());

        // remove original ER
        asicContent.setEvidenceRecordDocuments(null);

        // set filename
        DefaultASiCWithCAdESFilenameFactory filenameFactory = new DefaultASiCWithCAdESFilenameFactory();
        String erFilename = filenameFactory.getEvidenceRecordFilename(asicContent, EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD);
        erDocument.setName(erFilename);

        // return the ER
        return erDocument;
    }

    private DSSDocument createERManifestDocument(ASiCContent asicContent, DSSDocument erDocument) {
        asicContent.setEvidenceRecordManifestDocuments(null);

        ASiCEvidenceRecordManifestBuilder manifestBuilder = new ASiCEvidenceRecordManifestBuilder(asicContent,
                DigestAlgorithm.SHA256, erDocument.getName())
                .setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter())
                .setEvidenceRecordFilenameFactory(new DefaultASiCWithCAdESFilenameFactory());
        return manifestBuilder.build();
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertNotNull(diagnosticData.getContainerType());
        assertNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
    }

    @Override
    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
        assertEquals(1, digestMatchers.size());

        XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
        assertEquals(DigestMatcherType.MESSAGE_IMPRINT, xmlDigestMatcher.getType());
        assertTrue(xmlDigestMatcher.isDataFound());
        assertTrue(xmlDigestMatcher.isDataIntact());
    }

}
