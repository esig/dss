package eu.europa.esig.dss.asic.xades.evidencerecord;

import eu.europa.esig.dss.asic.common.ASiCEvidenceRecordFilenameFactory;
import eu.europa.esig.dss.asic.common.evidencerecord.AbstractASiCContainerEvidenceRecordBuilder;
import eu.europa.esig.dss.asic.common.signature.AbstractASiCContentBuilder;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESASiCContentBuilder;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;

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

}
