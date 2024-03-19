package eu.europa.esig.dss.asic.xades.extract;

import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractorFactory;
import eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESValidatorFactory;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.Objects;

/**
 * This class is used to load a corresponding {@code eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger}
 * for an ASiC with XAdES container
 *
 */
public class ASiCWithXAdESContainerExtractorFactory implements ASiCContainerExtractorFactory {

    /**
     * Default constructor
     */
    public ASiCWithXAdESContainerExtractorFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument asicContainer) {
        Objects.requireNonNull(asicContainer, "ASiC container cannot be null!");

        final ASiCContainerWithXAdESValidatorFactory documentValidatorFactory = new ASiCContainerWithXAdESValidatorFactory();
        return documentValidatorFactory.isSupported(asicContainer);
    }

    @Override
    public ASiCContainerExtractor create(DSSDocument asicContainer) {
        Objects.requireNonNull(asicContainer, "ASiC container cannot be null!");
        if (!isSupported(asicContainer)) {
            throw new UnsupportedOperationException(
                    "The ASiC container is not supported by ASiC with XAdES container extractor factory!");
        }
        return new ASiCWithXAdESContainerExtractor(asicContainer);
    }

}
