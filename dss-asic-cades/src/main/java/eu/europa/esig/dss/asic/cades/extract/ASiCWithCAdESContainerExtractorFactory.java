package eu.europa.esig.dss.asic.cades.extract;

import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESAnalyzerFactory;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.extract.ASiCContainerExtractorFactory;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.Objects;

/**
 * This class is used to load a corresponding {@code eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger}
 * for an ASiC with CAdES container
 *
 */
public class ASiCWithCAdESContainerExtractorFactory implements ASiCContainerExtractorFactory {

    /**
     * Default constructor
     */
    public ASiCWithCAdESContainerExtractorFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument asicContainer) {
        Objects.requireNonNull(asicContainer, "ASiC container cannot be null!");

        final ASiCContainerWithCAdESAnalyzerFactory documentValidatorFactory = new ASiCContainerWithCAdESAnalyzerFactory();
        return documentValidatorFactory.isSupported(asicContainer);
    }

    @Override
    public ASiCContainerExtractor create(DSSDocument asicContainer) {
        Objects.requireNonNull(asicContainer, "ASiC container cannot be null!");
        if (!isSupported(asicContainer)) {
            throw new UnsupportedOperationException(
                    "The ASiC container is not supported by ASiC with CAdES container extractor factory!");
        }
        return new ASiCWithCAdESContainerExtractor(asicContainer);
    }

}
