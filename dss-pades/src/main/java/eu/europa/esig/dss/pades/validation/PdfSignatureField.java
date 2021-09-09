package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.SigFieldPermissions;

/**
 * Object of this interface represents a PDF Signature field
 *
 */
public class PdfSignatureField {

    /** Represents an extracted /Lock dictionary (optional) */
    private final PdfDict sigFieldDict;

    /**
     * Default constructor
     *
     * @param sigFieldDict {@link PdfDict}
     */
    public PdfSignatureField(final PdfDict sigFieldDict) {
        this.sigFieldDict = sigFieldDict;
    }

    /**
     * This method returns a signature field's name
     *
     * @return {@link String} name
     */
    public String getFieldName() {
        return sigFieldDict.getStringValue(PAdESConstants.FIELD_NAME_NAME);
    }

    /**
     * Returns a /Lock dictionary content, when present
     *
     * @return {@link SigFieldPermissions}
     */
    public SigFieldPermissions getLockDictionary() {
        PdfDict lock = sigFieldDict.getAsDict(PAdESConstants.LOCK_NAME);
        if (lock != null) {
            return PAdESUtils.extractPermissionsDictionary(lock);
        }
        return null;
    }

    @Override
    public String toString() {
        return "PdfSignatureField {" +"name=" + getFieldName() + '}';
    }

}
