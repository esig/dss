package eu.europa.esig.dss.tsl.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.tsl.OtherTSLPointer;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.parsing.ParsingUtils;

/**
 * This class creates an instance of {@code eu.europa.esig.dss.tsl.runnable.PivotProcessingResult}
 * from a given {@code CacheAccessByKey}
 *
 */
public class PivotProcessingResultFromCacheAccessBuilder {

    /** Cache access to the given pivot */
    private final CacheAccessByKey cacheAccessByKey;

    /**
     * Default constructor
     *
     * @param cacheAccessByKey {@link CacheAccessByKey}
     */
    public PivotProcessingResultFromCacheAccessBuilder(final CacheAccessByKey cacheAccessByKey) {
        this.cacheAccessByKey = cacheAccessByKey;
    }

    /**
     * Builds the {@code PivotProcessingResult}
     *
     * @return {@link PivotProcessingResult}
     */
    public PivotProcessingResult build() {
        OtherTSLPointer xmlLotlPointer = ParsingUtils.getXMLLOTLPointer(cacheAccessByKey.getParsingReadOnlyResult());
        return new PivotProcessingResult(getDocument(), getCertificateSource(xmlLotlPointer), getLotlLocation(xmlLotlPointer));
    }

    private DSSDocument getDocument() {
        if (cacheAccessByKey.getDownloadReadOnlyResult() != null) {
            return cacheAccessByKey.getDownloadReadOnlyResult().getDocument();
        }
        return null;
    }

    private CertificateSource getCertificateSource(OtherTSLPointer xmlLotlPointer) {
        if (xmlLotlPointer != null) {
            return ParsingUtils.getLOTLAnnouncedCertificateSource(xmlLotlPointer);
        }
        return null;
    }

    private String getLotlLocation(OtherTSLPointer xmlLotlPointer) {
        if (xmlLotlPointer != null) {
            return xmlLotlPointer.getTSLLocation();
        }
        return null;
    }

}
