package eu.europa.esig.dss.asic.xades.merge;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger;
import eu.europa.esig.dss.asic.common.merge.ASiCContainerMergerFactory;
import eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESValidatorFactory;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to load a relevant merger for an ASiC with XAdES containers
 *
 */
public class ASiCWithXAdESContainerMergerFactory implements ASiCContainerMergerFactory {

    @Override
    public boolean isSupported(DSSDocument containerOne, DSSDocument containerTwo) {
        ASiCContainerWithXAdESValidatorFactory documentValidatorFactory = new ASiCContainerWithXAdESValidatorFactory();
        return documentValidatorFactory.isSupported(containerOne) && documentValidatorFactory.isSupported(containerTwo);
    }

    @Override
    public ASiCContainerMerger create(DSSDocument containerOne, DSSDocument containerTwo) {
        boolean isFirstDocAsics = new ASiCSWithXAdESContainerMerger().isSupported(containerOne);
        boolean isSecondDocAsics = new ASiCSWithXAdESContainerMerger().isSupported(containerTwo);
        if (isFirstDocAsics && isSecondDocAsics) {
            return new ASiCSWithXAdESContainerMerger(containerOne, containerTwo);
        } else if (!isFirstDocAsics && !isSecondDocAsics) {
            return new ASiCEWithXAdESContainerMerger(containerOne, containerTwo);
        }
        throw new UnsupportedOperationException(
                "Unable to create an ASiCContainerMerger for two documents of different ASiCContainer types!");
    }

    @Override
    public boolean isSupported(ASiCContent asicContentOne, ASiCContent asicContentTwo) {
        ASiCContainerWithXAdESValidatorFactory documentValidatorFactory = new ASiCContainerWithXAdESValidatorFactory();
        return documentValidatorFactory.isSupported(asicContentOne) && documentValidatorFactory.isSupported(asicContentTwo);
    }

    @Override
    public ASiCContainerMerger create(ASiCContent contentOne, ASiCContent contentTwo) {
        return null;
    }

}
