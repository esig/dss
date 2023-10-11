package eu.europa.esig.dss.pki.jaxb.builder;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.pki.exception.PKIException;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Builds a key pair given the provided {@code EncryptionAlgorithm} and key size
 *
 */
public class KeyPairBuilder {

    /** Encryption algorithm to generate a key pair for */
    private final EncryptionAlgorithm encryptionAlgorithm;

    /** The key size of the generated key pair */
    private final Integer keySize;

    /**
     * Default constructor
     *
     * @param encryptionAlgorithm {@link EncryptionAlgorithm} the encryption algorithm to generate a key pair for
     * @param keySize the key length
     */
    public KeyPairBuilder(final EncryptionAlgorithm encryptionAlgorithm, final Integer keySize) {
        Objects.requireNonNull(encryptionAlgorithm, "EncryptionAlgorithm cannot be null!");
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.keySize = keySize;
    }

    /**
     * Builds a KeyPair
     *
     * @return {@link KeyPair}
     */
    public KeyPair build() {
        try {
            if (EncryptionAlgorithm.ECDSA.isEquivalent(encryptionAlgorithm)) {
                ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(getEllipticCurveName());
                KeyPairGenerator generator = KeyPairGenerator.getInstance(encryptionAlgorithm.getName(), DSSSecurityProvider.getSecurityProvider());
                generator.initialize(ecSpec, new SecureRandom());
                return generator.generateKeyPair();
            } else if (EncryptionAlgorithm.X25519 == encryptionAlgorithm) {
                KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(SignatureAlgorithm.ED25519.getJCEId(), DSSSecurityProvider.getSecurityProvider());
                return keyGenerator.generateKeyPair();
            } else if (EncryptionAlgorithm.X448 == encryptionAlgorithm) {
                KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(SignatureAlgorithm.ED448.getJCEId(), DSSSecurityProvider.getSecurityProvider());
                return keyGenerator.generateKeyPair();
            } else if (EncryptionAlgorithm.EDDSA == encryptionAlgorithm) {
                throw new UnsupportedOperationException("Please define one of X25519 or X448 EncryptionAlgorithm explicitly.");
            } else {
                Objects.requireNonNull(keySize, "KeyLength shall be defined!");
                KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(encryptionAlgorithm.getName(), DSSSecurityProvider.getSecurityProvider());
                keyGenerator.initialize(keySize);
                return keyGenerator.generateKeyPair();
            }
        } catch (GeneralSecurityException e) {
            throw new PKIException("Unable to build a key pair.", e);
        }
    }

    private String getEllipticCurveName() {
        if (keySize != null) {
            return String.format("secp%sr1", keySize);
        } else {
            return "prime256v1";
        }
    }

}
