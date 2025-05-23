package eu.europa.esig.dss.asic.xades.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCEvidenceRecordFilenameFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.AbstractASiCContainerEvidenceRecordBuilder;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCContentBuilder;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESASiCContentBuilder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * Validates and incorporates an existing Evidence Record within an ASiC with XAdES container
 *
 */
public class ASiCWithXAdESContainerEvidenceRecordBuilder extends AbstractASiCContainerEvidenceRecordBuilder {

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param asicFilenameFactory {@link ASiCEvidenceRecordFilenameFactory}
     */
    public ASiCWithXAdESContainerEvidenceRecordBuilder(final CertificateVerifier certificateVerifier,
                                                       final ASiCEvidenceRecordFilenameFactory asicFilenameFactory) {
        super(certificateVerifier, asicFilenameFactory);
    }

    @Override
    protected AbstractASiCContentBuilder getASiCContentBuilder() {
        return new ASiCWithXAdESASiCContentBuilder();
    }

    @Override
    protected void assertEvidenceRecordValid(EvidenceRecord evidenceRecord, ASiCContent asicContent) {
        List<DSSDocument> evidenceRecordDocuments = asicContent.getEvidenceRecordDocuments();
        if (Utils.isCollectionNotEmpty(evidenceRecordDocuments)) {
            String evidenceRecordFilename = asicFilenameFactory.getEvidenceRecordFilename(asicContent, evidenceRecord.getEvidenceRecordType());
            if (DSSUtils.getDocumentNames(evidenceRecordDocuments).contains(evidenceRecordFilename)) {
                throw new IllegalInputException(String.format("The ASiC container already contains a file with name '%s'! " +
                        "Addition of an evidence record of the same type is not allowed for ASiC with XAdES container.", evidenceRecordFilename));
            }
        }

        super.assertEvidenceRecordValid(evidenceRecord, asicContent);
    }

}
