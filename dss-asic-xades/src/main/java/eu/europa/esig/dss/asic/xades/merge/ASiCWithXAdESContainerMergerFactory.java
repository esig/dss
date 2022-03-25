package eu.europa.esig.dss.asic.xades.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger;
import eu.europa.esig.dss.asic.common.merge.ASiCContainerMergerFactory;
import eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESValidatorFactory;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.Objects;

/**
 * This class is used to load a relevant merger for an ASiC with XAdES containers
 *
 */
public class ASiCWithXAdESContainerMergerFactory implements ASiCContainerMergerFactory {

    @Override
    public boolean isSupported(DSSDocument... containers) {
        Objects.requireNonNull(containers, "Containers shall be provided!");
        if (containers.length == 0) {
            throw new NullPointerException("At least one container shall be provided!");
        }
        ASiCContainerWithXAdESValidatorFactory documentValidatorFactory = new ASiCContainerWithXAdESValidatorFactory();
        for (DSSDocument container : containers) {
            if (container == null) {
                throw new NullPointerException("A document cannot be null!");
            }

            if (!documentValidatorFactory.isSupported(container)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public ASiCContainerMerger create(DSSDocument... containers) {
        Objects.requireNonNull(containers, "Containers shall be provided!");
        if (containers.length == 0) {
            throw new NullPointerException("At least one container shall be provided!");
        }
        Boolean isASiCS = null;
        for (DSSDocument container : containers) {
            if (container == null) {
                throw new NullPointerException("A document cannot be null!");
            }

            boolean asicsContainer = new ASiCSWithXAdESContainerMerger().isSupported(container);
            boolean asiceContainer = new ASiCEWithXAdESContainerMerger().isSupported(container);
            if (asicsContainer && asiceContainer) {
                // skip verification if a container is supported by any merger
                continue;
            } else if (!asicsContainer && !asiceContainer) {
                throw new UnsupportedOperationException(String.format(
                        "The container with name '%s' is not supported by ASiC with XAdES merger!", container.getName()));
            }

            if (isASiCS == null) {
                isASiCS = asicsContainer;

            } else if (isASiCS ^ asicsContainer) {
                throw new UnsupportedOperationException(
                        "Unable to create an ASiCContainerMerger for two documents of different ASiCContainer types!");
            }
        }
        if (isASiCS != null && isASiCS) {
            return new ASiCSWithXAdESContainerMerger(containers);
        } else {
            return new ASiCEWithXAdESContainerMerger(containers);
        }
    }

    @Override
    public boolean isSupported(ASiCContent... asicContents) {
        Objects.requireNonNull(asicContents, "ASiCContents shall be provided!");
        if (asicContents.length == 0) {
            throw new NullPointerException("At least one ASiCContent shall be provided!");
        }
        ASiCContainerWithXAdESValidatorFactory documentValidatorFactory = new ASiCContainerWithXAdESValidatorFactory();
        for (ASiCContent asicContent : asicContents) {
            if (asicContent == null) {
                throw new NullPointerException("An ASiCContent cannot be null!");
            }

            if (!documentValidatorFactory.isSupported(asicContent)) {
                return false;
            }
        }
        return true;
    }

    @Override
    public ASiCContainerMerger create(ASiCContent... asicContents) {
        Objects.requireNonNull(asicContents, "ASiCContents shall be provided!");
        if (asicContents.length == 0) {
            throw new NullPointerException("At least one ASiCContent shall be provided!");
        }
        Boolean isASiCS = null;
        for (ASiCContent asicContent : asicContents) {
            if (asicContent == null) {
                throw new NullPointerException("An ASiCContent cannot be null!");
            }

            boolean asicsContainer = new ASiCSWithXAdESContainerMerger().isSupported(asicContent);
            boolean asiceContainer = new ASiCEWithXAdESContainerMerger().isSupported(asicContent);
            if (asicsContainer && asiceContainer) {
                // skip verification if a container is supported by any merger
                continue;
            } else if (!asicsContainer && !asiceContainer) {
                throw new UnsupportedOperationException("An ASiCContent is not supported by ASiC with XAdES merger!");
            }

            if (isASiCS == null) {
                isASiCS = asicsContainer;

            } else if (isASiCS ^ asicsContainer) {
                throw new UnsupportedOperationException(
                        "Unable to create an ASiCContainerMerger for two documents of different ASiCContainer types!");
            }
        }
        if (isASiCS != null && isASiCS) {
            return new ASiCSWithXAdESContainerMerger(asicContents);
        } else {
            return new ASiCEWithXAdESContainerMerger(asicContents);
        }
    }

}
