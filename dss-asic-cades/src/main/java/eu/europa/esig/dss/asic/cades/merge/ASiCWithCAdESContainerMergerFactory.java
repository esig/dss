package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidatorFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger;
import eu.europa.esig.dss.asic.common.merge.ASiCContainerMergerFactory;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.Objects;

/**
 * This class is used to load a relevant merger for an ASiC with CAdES containers
 *
 */
public class ASiCWithCAdESContainerMergerFactory implements ASiCContainerMergerFactory {

    @Override
    public boolean isSupported(DSSDocument... containers) {
        Objects.requireNonNull(containers, "Containers shall be provided!");
        if (containers.length == 0) {
            throw new NullPointerException("At least one container shall be provided!");
        }
        ASiCContainerWithCAdESValidatorFactory documentValidatorFactory = new ASiCContainerWithCAdESValidatorFactory();
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

            boolean asicsContainer = new ASiCSWithCAdESContainerMerger().isSupported(container);
            boolean asiceContainer = new ASiCEWithCAdESContainerMerger().isSupported(container);
            if (asicsContainer && asiceContainer) {
                // skip verification if a container is supported by any merger
                continue;
            } else if (!asicsContainer && !asiceContainer) {
                throw new UnsupportedOperationException(String.format(
                        "The container with name '%s' is not supported by ASiC with CAdES merger!", container.getName()));
            }

            if (isASiCS == null) {
                isASiCS = asicsContainer;

            } else if (isASiCS ^ asicsContainer) {
                throw new UnsupportedOperationException(
                        "Unable to create an ASiCContainerMerger for documents of different ASiCContainer types!");
            }
        }
        if (isASiCS != null && isASiCS) {
            return new ASiCSWithCAdESContainerMerger(containers);
        } else {
            return new ASiCEWithCAdESContainerMerger(containers);
        }
    }

    @Override
    public boolean isSupported(ASiCContent... asicContents) {
        Objects.requireNonNull(asicContents, "ASiCContents shall be provided!");
        if (asicContents.length == 0) {
            throw new NullPointerException("At least one ASiCContent shall be provided!");
        }
        ASiCContainerWithCAdESValidatorFactory documentValidatorFactory = new ASiCContainerWithCAdESValidatorFactory();
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

            boolean asicsContainer = new ASiCSWithCAdESContainerMerger().isSupported(asicContent);
            boolean asiceContainer = new ASiCEWithCAdESContainerMerger().isSupported(asicContent);
            if (asicsContainer && asiceContainer) {
                // skip verification if a container is supported by any merger
                continue;
            } else if (!asicsContainer && !asiceContainer) {
                throw new UnsupportedOperationException("An ASiCContent is not supported by ASiC with CAdES merger!");
            }

            if (isASiCS == null) {
                isASiCS = asicsContainer;

            } else if (isASiCS ^ asicsContainer) {
                throw new UnsupportedOperationException(
                        "Unable to create an ASiCContainerMerger for documents of different ASiCContainer types!");
            }
        }
        if (isASiCS != null && isASiCS) {
            return new ASiCSWithCAdESContainerMerger(asicContents);
        } else {
            return new ASiCEWithCAdESContainerMerger(asicContents);
        }
    }

}
