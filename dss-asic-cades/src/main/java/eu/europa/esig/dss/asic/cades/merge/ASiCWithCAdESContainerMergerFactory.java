package eu.europa.esig.dss.asic.cades.merge;

import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidatorFactory;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger;
import eu.europa.esig.dss.asic.common.merge.ASiCContainerMergerFactory;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to load a relevant merger for an ASiC with CAdES containers
 *
 */
public class ASiCWithCAdESContainerMergerFactory implements ASiCContainerMergerFactory {

    @Override
    public boolean isSupported(DSSDocument containerOne, DSSDocument containerTwo) {
        ASiCContainerWithCAdESValidatorFactory documentValidatorFactory = new ASiCContainerWithCAdESValidatorFactory();
        return documentValidatorFactory.isSupported(containerOne) && documentValidatorFactory.isSupported(containerTwo);
    }

    @Override
    public ASiCContainerMerger create(DSSDocument containerOne, DSSDocument containerTwo) {
        boolean isFirstDocAsics = new ASiCSWithCAdESContainerMerger().isSupported(containerOne);
        boolean isSecondDocAsics = new ASiCSWithCAdESContainerMerger().isSupported(containerTwo);
        if (isFirstDocAsics && isSecondDocAsics) {
            return new ASiCSWithCAdESContainerMerger(containerOne, containerTwo);
        } else if (!isFirstDocAsics && !isSecondDocAsics) {
            return new ASiCEWithCAdESContainerMerger(containerOne, containerTwo);
        }
        throw new UnsupportedOperationException(
                "Unable to create an ASiCContainerMerger for two documents of different ASiCContainer types!");
    }

    @Override
    public boolean isSupported(ASiCContent asicContentOne, ASiCContent asicContentTwo) {
        ASiCContainerWithCAdESValidatorFactory documentValidatorFactory = new ASiCContainerWithCAdESValidatorFactory();
        return documentValidatorFactory.isSupported(asicContentOne) && documentValidatorFactory.isSupported(asicContentTwo);
    }

    @Override
    public ASiCContainerMerger create(ASiCContent contentOne, ASiCContent contentTwo) {
        return null;
    }

}
