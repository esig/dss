package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.validation.SignaturePolicy;
import org.w3c.dom.Element;

import java.util.Collections;
import java.util.List;

/**
 * Represents a signature policy extracted from a XAdES (XML) signature
 *
 */
public class XAdESSignaturePolicy extends SignaturePolicy {

    /** The transforms Element (used in XAdES) */
    private Element transforms;

    /** Represents the xades:SigPolicyQualifiers element */
    private Element sigPolicyQualifiers;

    /**
     * The default constructor for XAdESSignaturePolicy. It represents the implied policy.
     */
    public XAdESSignaturePolicy() {
        super();
    }

    /**
     * The default constructor for XAdESSignaturePolicy.
     *
     * @param identifier
     *            the policy identifier
     */
    public XAdESSignaturePolicy(final String identifier) {
        super(identifier);
    }

    /**
     * Returns a 'ds:Transforms' element if found
     * NOTE: XAdES only
     *
     * @return 'ds:Transforms' {@link Element} if found, NULL otherwise
     */
    public Element getTransforms() {
        return transforms;
    }

    /**
     * Sets a 'ds:Transforms' node
     *
     * @param transforms {@link Element}
     */
    public void setTransforms(Element transforms) {
        this.transforms = transforms;
    }

    /**
     * Gets a list of Strings describing the 'ds:Transforms' element
     * NOTE: XAdES only
     *
     * @return a description of 'ds:Transforms' if present, null otherwise
     */
    public List<String> getTransformsDescription() {
        if (transforms != null) {
            return new TransformsDescriptionBuilder(transforms).build();
        }
        return Collections.emptyList();
    }

    /**
     * Gets the xades:SigPolicyQualifiers element if present
     *
     * @return {@link Element}
     */
    public Element getSigPolicyQualifiers() {
        return sigPolicyQualifiers;
    }

    /**
     * Sets the xades:SigPolicyQualifiers element
     *
     * @param sigPolicyQualifiers {@link Element}
     */
    public void setSigPolicyQualifiers(Element sigPolicyQualifiers) {
        this.sigPolicyQualifiers = sigPolicyQualifiers;
    }

}
