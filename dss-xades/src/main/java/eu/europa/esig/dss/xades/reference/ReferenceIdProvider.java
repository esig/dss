package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

/**
 * This class is used to generate a deterministic reference identifier
 *
 */
public class ReferenceIdProvider {

    /** The signature parameters used to create the signature */
    private XAdESSignatureParameters signatureParameters;

    /**
     * id-prefix for ds:Reference element
     * Default : "r-"
     */
    private String referenceIdPrefix = "r";

    /** Internal reference id counter */
    private int index;

    /**
     * Default constructor
     */
    public ReferenceIdProvider() {
        // empty
    }

    /**
     * Sets signature parameters to build a deterministic identifier
     *
     * @param signatureParameters {@link XAdESSignatureParameters}
     */
    public void setSignatureParameters(XAdESSignatureParameters signatureParameters) {
        this.signatureParameters = signatureParameters;
    }

    /**
     * Sets the reference id prefix to be used on reference creation
     *
     * @param referenceIdPrefix {@link String} id prefix to use for references
     */
    public void setReferenceIdPrefix(String referenceIdPrefix) {
        if (Utils.isStringBlank(referenceIdPrefix)) {
            throw new IllegalArgumentException("The reference id prefix cannot be blank!");
        }
        this.referenceIdPrefix = referenceIdPrefix;
    }

    /**
     * This method returns the following signature reference identifier
     *
     * @return {@link String}
     */
    public String getReferenceId() {
        increaseIndex();

        final StringBuilder referenceId = new StringBuilder();
        referenceId.append(referenceIdPrefix);
        referenceId.append("-");
        if (signatureParameters != null) {
            referenceId.append(signatureParameters.getDeterministicId());
            referenceId.append("-");
        }
        referenceId.append(index);
        return referenceId.toString();
    }

    private void increaseIndex() {
        ++index;
    }

}
