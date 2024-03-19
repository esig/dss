package eu.europa.esig.dss.asic.xades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCContentDocumentFilterFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.ASiCEvidenceRecordManifestBuilder;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.DefaultASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithAsn1EvidenceRecordTestValidation;
import eu.europa.esig.dss.asic.xades.signature.DefaultASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ASiCEWithXAdESWrongEvidenceRecordFilenameValidationTest extends AbstractASiCWithAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        DSSDocument originalZip = new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.sce");

        ASiCContainerExtractor containerExtractor = DefaultASiCContainerExtractor.fromDocument(originalZip);
        ASiCContent asicContent = containerExtractor.extract();

        List<DSSDocument> evidenceRecordDocuments = asicContent.getEvidenceRecordDocuments();
        assertEquals(1, evidenceRecordDocuments.size());

        DSSDocument erDocument = evidenceRecordDocuments.get(0);

        DefaultASiCWithXAdESFilenameFactory filenameFactory = new DefaultASiCWithXAdESFilenameFactory();
        filenameFactory.setEvidenceRecordType(EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD);
        String erFilename = filenameFactory.getEvidenceRecordFilename(asicContent);
        erDocument.setName(erFilename);

        ASiCEvidenceRecordManifestBuilder manifestBuilder = new ASiCEvidenceRecordManifestBuilder(asicContent,
                DigestAlgorithm.SHA256, erDocument.getName())
                .setAsicContentDocumentFilter(ASiCContentDocumentFilterFactory.signedDocumentsOnlyFilter())
                .setEvidenceRecordFilenameFactory(new DefaultASiCWithXAdESFilenameFactory());
        DSSDocument erManifest = manifestBuilder.build();

        asicContent.setEvidenceRecordManifestDocuments(Collections.singletonList(erManifest));

        return ZipUtils.getInstance().createZipArchive(asicContent);
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        // ignored because if invalid filename
        assertEquals(0, detachedEvidenceRecords.size());
    }
    
}
