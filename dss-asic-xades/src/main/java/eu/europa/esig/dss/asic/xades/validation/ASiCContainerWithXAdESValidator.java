package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.validation.AbstractASiCContainerValidator;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is an implementation to validate ASiC containers with XAdES signature(s)
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public class ASiCContainerWithXAdESValidator extends AbstractASiCContainerValidator {

    /**
     * The empty constructor
     */
    ASiCContainerWithXAdESValidator() {
        super(new ASiCContainerWithXAdESAnalyzer());
    }

    /**
     * The default constructor
     *
     * @param asicContainer {@link DSSDocument} to be validated
     */
    public ASiCContainerWithXAdESValidator(final DSSDocument asicContainer) {
        super(new ASiCContainerWithXAdESAnalyzer(asicContainer));
    }

    /**
     * The constructor from {@code ASiCContent}
     *
     * @param asicContent {@link ASiCContent} to be validated
     */
    public ASiCContainerWithXAdESValidator(final ASiCContent asicContent) {
        super(new ASiCContainerWithXAdESAnalyzer(asicContent));
    }

    @Override
    public ASiCContainerWithXAdESAnalyzer getDocumentAnalyzer() {
        return (ASiCContainerWithXAdESAnalyzer) super.getDocumentAnalyzer();
    }

}