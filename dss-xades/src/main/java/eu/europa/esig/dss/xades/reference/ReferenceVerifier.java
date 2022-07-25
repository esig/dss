package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * This class is used to verify the validity of the {@code eu.europa.esig.dss.xades.reference.DSSReference}s setup
 *
 */
public class ReferenceVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(ReferenceVerifier.class);

    /**
     * The used XAdESSignatureParameters
     */
    private XAdESSignatureParameters signatureParameters;

    /**
     * The default constructor for a signature references verification
     *
     * @param signatureParameters {@link XAdESSignatureParameters}
     */
    public ReferenceVerifier(XAdESSignatureParameters signatureParameters) {
        this.signatureParameters = signatureParameters;
    }

    /**
     * Verifies a compatibility of defined signature parameters and reference transformations
     */
    public void checkReferencesValidity() {
        if (signatureParameters != null) {
            String referenceWrongMessage = "Reference setting is not correct! ";
            for (DSSReference reference : signatureParameters.getReferences()) {
                if (reference.getObject() != null) {
                    LOG.debug("ds:Object is defined for reference with Id '{}'. Use the provided value.", reference.getId());
                    continue;
                }
                List<DSSTransform> transforms = reference.getTransforms();
                if (Utils.isCollectionNotEmpty(transforms)) {
                    for (DSSTransform transform : transforms) {
                        if (Transforms.TRANSFORM_BASE64_DECODE.equals(transform.getAlgorithm())) {
                            if (signatureParameters.isEmbedXML()) {
                                throw new IllegalArgumentException(referenceWrongMessage + "The embedXML(true) parameter is not compatible with base64 transform.");
                            } else if (signatureParameters.isManifestSignature()) {
                                throw new IllegalArgumentException(referenceWrongMessage + "Manifest signature is not compatible with base64 transform.");
                            } else if (!SignaturePackaging.ENVELOPING.equals(signatureParameters.getSignaturePackaging())) {
                                throw new IllegalArgumentException(referenceWrongMessage +
                                        String.format("Base64 transform is not compatible with %s signature format.", signatureParameters.getSignaturePackaging()));
                            } else if (transforms.size() > 1) {
                                throw new IllegalArgumentException(referenceWrongMessage + "Base64 transform cannot be used with other transformations.");
                            }
                        }
                    }

                } else {
                    String uri = reference.getUri();
                    if (Utils.isStringBlank(uri) || DomUtils.isElementReference(uri)) {
                        LOG.warn("A reference with id='{}' and uri='{}' points to an XML Node, while no transforms are defined! "
                                + "The configuration can lead to an unexpected result!", reference.getId(), uri);
                    }
                    if (SignaturePackaging.ENVELOPED.equals(signatureParameters.getSignaturePackaging()) && Utils.isStringBlank(uri)) {
                        throw new IllegalArgumentException(referenceWrongMessage + "Enveloped signature must have an enveloped transformation!");
                    }

                }
            }
        }
    }

}
