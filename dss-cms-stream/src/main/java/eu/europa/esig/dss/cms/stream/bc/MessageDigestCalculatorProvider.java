package eu.europa.esig.dss.cms.stream.bc;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.OutputStream;

/**
 * DigestCalculatorProvider implementation based on {@code DSSMessageDigestCalculator}
 *
 */
public class MessageDigestCalculatorProvider implements DigestCalculatorProvider {

    /**
     * Default constructor
     */
    public MessageDigestCalculatorProvider() {
        // empty
    }

    @Override
    public DigestCalculator get(final AlgorithmIdentifier algorithm) throws OperatorCreationException {
        final DSSMessageDigestCalculator messageDigestCalculator;

        DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(algorithm.getAlgorithm().getId());
        messageDigestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);

        return new DigestCalculator() {
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return algorithm;
            }

            public OutputStream getOutputStream() {
                return messageDigestCalculator.getOutputStream(new OutputStream() {
                    // Use no-sense OutputStream
                    @Override
                    public void write(int b) {
                        // skip
                    }
                    @Override
                    public void write(byte[] b) {
                        // skip
                    }
                    @Override
                    public void write(byte[] b, int off, int len) {
                        // skip
                    }
                });
            }

            public byte[] getDigest() {
                return messageDigestCalculator.getMessageDigest(digestAlgorithm).getValue();
            }
        };
    }

}
