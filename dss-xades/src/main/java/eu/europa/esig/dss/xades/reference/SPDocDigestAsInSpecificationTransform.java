package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import org.w3c.dom.Node;

/**
 * This is a special transform to be used exclusively within a xades:SignaturePolicyId
 * to define special digest computation rules.
 * See EN 319 132-1 "5.2.9 The SignaturePolicyIdentifier qualifying property"
 *
 */
public class SPDocDigestAsInSpecificationTransform extends AbstractTransform {

    /** The SPDocDigestAsInSpecification algorithm URI */
    private static final String ALGORITHM_URI = DSSXMLUtils.SP_DOC_DIGEST_AS_IN_SPECIFICATION_ALGORITHM_URI;

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
