package eu.europa.esig.dss.asic.xades.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.merge.DefaultContainerMerger;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.asic.xades.signature.DefaultASiCWithXAdESFilenameFactory;
import eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESValidatorFactory;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.Objects;

/**
 * This class contains common code for ASiC with XAdES container merger classes.
 *
 */
public abstract class AbstractASiCWithXAdESContainerMerger extends DefaultContainerMerger {

    /**
     * Defines rules for filename creation for new ZIP entries (e.g. signature files, etc.)
     */
    protected ASiCWithXAdESFilenameFactory asicFilenameFactory = new DefaultASiCWithXAdESFilenameFactory();

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

    /**
     * Sets {@code ASiCWithXAdESFilenameFactory} defining a set of rules for naming of newly create ZIP entries,
     * such as signature files.
     *
     * @param asicFilenameFactory {@link ASiCWithXAdESFilenameFactory}
     */
    public void setAsicFilenameFactory(ASiCWithXAdESFilenameFactory asicFilenameFactory) {
        Objects.requireNonNull(asicFilenameFactory, "ASiCWithXAdESFilenameFactory cannot be null!");
        this.asicFilenameFactory = asicFilenameFactory;
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
