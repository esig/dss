package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

/**
 * An abstract class for PDF lock dictionary validation
 *
 */
public abstract class AbstractPdfLockDictionaryCheck extends ChainItem<XmlFC> {

    /** The PDF signature to be checked */
    protected final SignatureWrapper signature;

    /** Corresponding lock dictionary */
    protected final XmlPDFLockDictionary pdfLockDictionary;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param signature {@link SignatureWrapper}
     * @param pdfLockDictionary {@link XmlPDFLockDictionary}
     * @param constraint {@link LevelConstraint}
     */
    public AbstractPdfLockDictionaryCheck(I18nProvider i18nProvider, XmlFC result,
                                          SignatureWrapper signature, XmlPDFLockDictionary pdfLockDictionary,
                                          LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.signature = signature;
        this.pdfLockDictionary = pdfLockDictionary;
    }

    @Override
    protected boolean process() {
        if (!signature.arePdfObjectModificationsDetected()) {
            return true;
        }
        if (pdfLockDictionary == null) {
            return true;
        }

        List<String> modifiedFieldNames = signature.getModifiedFieldNames();
        if (Utils.isCollectionEmpty(modifiedFieldNames)) {
            return true;
        }

        List<String> lockedFields = pdfLockDictionary.getFields();
        if (pdfLockDictionary.getAction() != null) {
            switch (pdfLockDictionary.getAction()) {
                case ALL:
                    return false;

                case EXCLUDE:
                    for (String fieldName : modifiedFieldNames) {
                        if (!lockedFields.contains(fieldName)) {
                            return false;
                        }
                    }
                    return true;

                case INCLUDE:
                    for (String fieldName : modifiedFieldNames) {
                        if (lockedFields.contains(fieldName)) {
                            return false;
                        }
                    }
                    return true;

                default:
                    throw new UnsupportedOperationException(
                            String.format("The value '%s' is not supported!", pdfLockDictionary.getAction()));
            }
        }
        return true;
    }

}
