package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.policy.DefaultSignaturePolicyValidatorLoader;
import eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
import eu.europa.esig.dss.xades.validation.policy.XMLSignaturePolicyValidator;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Loads a respective {@code eu.europa.esig.dss.validation.policy.SignaturePolicyValidator} for a XAdES signature
 *
 */
public class XAdESSignaturePolicyValidatorLoader extends DefaultSignaturePolicyValidatorLoader {

    /** The SPDocDigestAsInSpecification algorithm URI */
    private static final String SP_DOC_DIGEST_AS_IN_SPECIFICATION_ALGORITHM_URI =
            "http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification";

    @Override
    public SignaturePolicyValidator loadValidator(SignaturePolicy signaturePolicy) {
        if (!(signaturePolicy instanceof XAdESSignaturePolicy)) {
            throw new IllegalArgumentException("Only XAdESSignaturePolicy is supported by XAdESSignaturePolicyValidatorLoader!");
        }
        XAdESSignaturePolicy xadesSignaturePolicy = (XAdESSignaturePolicy) signaturePolicy;
        if (isHashComputationAsInPolicySpecification(xadesSignaturePolicy)) {
            return super.loadValidator(signaturePolicy);
        } else {
            return new XMLSignaturePolicyValidator();
        }
    }

    private boolean isHashComputationAsInPolicySpecification(XAdESSignaturePolicy xadesSignaturePolicy) {
        Element transforms = xadesSignaturePolicy.getTransforms();
        if (transforms != null && transforms.hasChildNodes()) {
            NodeList transformList = DomUtils.getNodeList(transforms, XMLDSigPaths.TRANSFORM_PATH);
            if (transformList.getLength() == 1) {
                Node transform = transformList.item(0);
                String algorithm = DomUtils.getValue(transform, "@Algorithm");
                if (SP_DOC_DIGEST_AS_IN_SPECIFICATION_ALGORITHM_URI.equals(algorithm)) {
                    return true;
                }
            }
        }
        return false;
    }

}
