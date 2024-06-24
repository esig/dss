package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.bouncycastle.cms.CMSSignedData;

/**
 * Validation of CMS document
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public class CMSDocumentValidator extends SignedDocumentValidator {

    /** The CMSSignedData to be validated */
    protected CMSSignedData cmsSignedData;

    /**
     * Default constructor
     */
    CMSDocumentValidator() {
        super(new CMSDocumentAnalyzer());
    }

    /**
     * The default constructor for {@code CMSDocumentValidator}.
     *
     * @param cmsSignedData
     *            pkcs7-signature(s)
     */
    public CMSDocumentValidator(final CMSSignedData cmsSignedData) {
        super(new CMSDocumentAnalyzer(cmsSignedData));
    }

    /**
     * The default constructor for {@code CMSDocumentValidator}.
     *
     * @param document
     *            document to validate (with the signature(s))
     */
    public CMSDocumentValidator(final DSSDocument document) {
        super(new CMSDocumentAnalyzer(document));
    }

    @Override
    public CMSDocumentAnalyzer getDocumentAnalyzer() {
        return (CMSDocumentAnalyzer) super.getDocumentAnalyzer();
    }

    /**
     * This method returns a CMSSignedData
     *
     * @return {@link CMSSignedData}
     */
    public CMSSignedData getCmsSignedData() {
        return getDocumentAnalyzer().getCmsSignedData();
    }

    @Override
    protected CAdESDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
        return new CAdESDiagnosticDataBuilder();
    }

}