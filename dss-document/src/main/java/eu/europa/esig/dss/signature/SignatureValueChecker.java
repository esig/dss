package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.DSSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * This class is used to verify whether the given {@code SignatureValue} is valid and
 * corresponds to the target {@link eu.europa.esig.dss.enumerations.SignatureAlgorithm}.
 *
 */
public class SignatureValueChecker {

    private static final Logger LOG = LoggerFactory.getLogger(SignatureValueChecker.class);

    /**
     * Default constructor
     */
    public SignatureValueChecker() {
        // empty
    }

    /**
     * This method ensures the provided {@code signatureValue} has the expected {@code targetSignatureAlgorithm}
     *
     * @param signatureValue
     *            {@link SignatureValue} obtained from a signing token
     * @param targetSignatureAlgorithm
     *            {@link SignatureAlgorithm} to convert the signatureValue to
     * @return {@link SignatureValue} with the defined {@code SignatureAlgorithm} in parameters
     */
    public SignatureValue ensureSignatureValue(SignatureValue signatureValue, SignatureAlgorithm targetSignatureAlgorithm) {
        Objects.requireNonNull(targetSignatureAlgorithm, "The target SignatureAlgorithm shall be defined within SignatureParameters!");

        if (signatureValue == null) {
            LOG.debug("The SignatureValue is not provided. Cannot verify the value.");
            return null;
        }

        if (targetSignatureAlgorithm.equals(signatureValue.getAlgorithm())) {
            LOG.debug("The created SignatureValue matches the defined target SignatureAlgorithm : '{}'", targetSignatureAlgorithm);
            return signatureValue;
        }

        final DigestAlgorithm expectedDigestAlgorithm = targetSignatureAlgorithm.getDigestAlgorithm();
        final DigestAlgorithm signatureDigestAlgorithm = signatureValue.getAlgorithm() != null ?
                signatureValue.getAlgorithm().getDigestAlgorithm() : null;
        if (!expectedDigestAlgorithm.equals(signatureDigestAlgorithm)) {
            throw new DSSException(String.format("The DigestAlgorithm within the SignatureValue '%s' " +
                    "does not match the expected value : '%s'", expectedDigestAlgorithm, signatureDigestAlgorithm));
        }

        if (EncryptionAlgorithm.ECDSA.isEquivalent(targetSignatureAlgorithm.getEncryptionAlgorithm())) {
            SignatureValue newSignatureValue = DSSUtils.convertECSignatureValue(targetSignatureAlgorithm, signatureValue);
            LOG.info("The algorithm '{}' has been obtained from the SignatureValue. The SignatureValue converted to " +
                    "the expected algorithm '{}'.", signatureValue.getAlgorithm(), targetSignatureAlgorithm);
            return newSignatureValue;
        }
        throw new DSSException(String.format("The SignatureAlgorithm within the SignatureValue '%s' " +
                        "does not match the expected value : '%s'. Conversion is not supported!",
                signatureValue.getAlgorithm(), targetSignatureAlgorithm));
    }

}
