package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.signature.SignatureExtension;
import eu.europa.esig.dss.signature.SigningOperation;

/**
 * JAdES extension
 *
 */
public interface JAdESLevelBaselineExtension extends SignatureExtension<JAdESSignatureParameters> {

    /**
     * Sets the signing operation
     *
     * NOTE: the internal variable, used in the signature creation/extension process
     *
     * @param signingOperation {@link SigningOperation}
     */
    void setOperationKind(SigningOperation signingOperation);

}
