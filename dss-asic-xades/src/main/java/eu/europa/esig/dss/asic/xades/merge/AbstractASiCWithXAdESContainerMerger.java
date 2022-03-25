package eu.europa.esig.dss.asic.xades.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.merge.DefaultContainerMerger;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESValidatorFactory;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class contains common code for ASiC with XAdES container merger classes.
 *
 */
public abstract class AbstractASiCWithXAdESContainerMerger extends DefaultContainerMerger {

    /**
     * Empty constructor
     */
    AbstractASiCWithXAdESContainerMerger() {
    }

    /**
     * This constructor is used to create an ASiC With XAdES container merger from provided container documents
     *
     * @param containers {@link DSSDocument}s representing ASiC containers to be merged
     */
    protected AbstractASiCWithXAdESContainerMerger(DSSDocument... containers) {
        super(containers);
    }

    /**
     * This constructor is used to create an ASiC With XAdES from to given {@code ASiCContent}s
     *
     * @param asicContents {@link ASiCContent}s to be merged
     */
    protected AbstractASiCWithXAdESContainerMerger(ASiCContent... asicContents) {
        super(asicContents);
    }

    @Override
    protected boolean isSupported(DSSDocument container) {
        return new ASiCContainerWithXAdESValidatorFactory().isSupported(container);
    }

    @Override
    protected boolean isSupported(ASiCContent asicContent) {
        return new ASiCContainerWithXAdESValidatorFactory().isSupported(asicContent);
    }

    @Override
    protected AbstractASiCContainerExtractor getContainerExtractor(DSSDocument container) {
        return new ASiCWithXAdESContainerExtractor(container);
    }

}
