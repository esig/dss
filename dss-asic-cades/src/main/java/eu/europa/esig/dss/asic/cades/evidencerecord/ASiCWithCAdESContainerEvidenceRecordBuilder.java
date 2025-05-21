package eu.europa.esig.dss.asic.cades.evidencerecord;

import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESASiCContentBuilder;
import eu.europa.esig.dss.asic.common.ASiCEvidenceRecordFilenameFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.AbstractASiCContainerEvidenceRecordBuilder;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCContentBuilder;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

/**
 * Validates and incorporates an existing Evidence Record within an ASiC with CAdES container
 *
 */
public class ASiCWithCAdESContainerEvidenceRecordBuilder extends AbstractASiCContainerEvidenceRecordBuilder {

    /**
     * Default constructor
     *
     * @param certificateVerifier {@link CertificateVerifier}
     * @param asicFilenameFactory {@link ASiCEvidenceRecordFilenameFactory}
     */
    public ASiCWithCAdESContainerEvidenceRecordBuilder(final CertificateVerifier certificateVerifier,
                                                          final ASiCEvidenceRecordFilenameFactory asicFilenameFactory) {
        super(certificateVerifier, asicFilenameFactory);
    }

    @Override
    protected AbstractASiCContentBuilder getASiCContentBuilder() {
        return new ASiCWithCAdESASiCContentBuilder();
    }

}
