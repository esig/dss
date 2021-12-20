package eu.europa.esig.dss.asic.common.signature;

import eu.europa.esig.dss.asic.common.ASiCContent;

/**
 * Represents an abstract class helping to extract a data to be signed for ASiC containers
 *
 */
public abstract class AbstractGetDataToSignHelper {

    /** The content of the ASiC container */
    private final ASiCContent asicContent;


    /**
     * The default constructor
     *
     * @param asicContent {@link ASiCContent}
     */
    protected AbstractGetDataToSignHelper(final ASiCContent asicContent) {
        this.asicContent = asicContent;
    }

    /**
     * This method returns {@link ASiCContent}
     *
     * @return {@link ASiCContent}
     */
    public ASiCContent getASiCContent() {
        return asicContent;
    }

}
