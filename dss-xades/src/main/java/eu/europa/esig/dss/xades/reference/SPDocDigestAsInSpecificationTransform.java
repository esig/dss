package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.definition.DSSNamespace;
import org.w3c.dom.Node;

/**
 * This is a special transform to be used exclusively within a xades:SignaturePolicyId
 * to define special digest computation rules.
 * See EN 319 132-1 "5.2.9 The SignaturePolicyIdentifier qualifying property"
 *
 */
public class SPDocDigestAsInSpecificationTransform extends AbstractTransform {

    /** The SPDocDigestAsInSpecification algorithm URI */
    private static final String ALGORITHM_URI = "http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification";

    /**
     * Default constructor with ds: xmldsig namespace
     */
    public SPDocDigestAsInSpecificationTransform() {
        super(ALGORITHM_URI);
    }

    /**
     * Constructor with a custom namespace
     *
     * @param xmlDSigNamespace {@link DSSNamespace}
     */
    protected SPDocDigestAsInSpecificationTransform(DSSNamespace xmlDSigNamespace) {
        super(xmlDSigNamespace, ALGORITHM_URI);
    }

    @Override
    public byte[] getBytesAfterTransformation(Node node) {
        throw new IllegalArgumentException(
                "The transform SPDocDigestAsInSpecificationTransform cannot be used for reference processing!");
    }

}
