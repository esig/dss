package eu.europa.esig.dss.cades.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;

public class CustomMessageDigestCalculatorProvider implements DigestCalculatorProvider {

	private static final Logger LOG = LoggerFactory.getLogger(CustomMessageDigestCalculatorProvider.class);

	private final DigestAlgorithm messageDigestAlgo;
	private final String messageDigestValueBase64;

	public CustomMessageDigestCalculatorProvider(DigestAlgorithm messageDigestAlgo, String messageDigestValueBase64) {
		this.messageDigestAlgo = messageDigestAlgo;
		this.messageDigestValueBase64 = messageDigestValueBase64;
	}

	@Override
	public DigestCalculator get(AlgorithmIdentifier digestAlgorithmIdentifier) throws OperatorCreationException {
		LOG.info("message-digest algorithm is set with {}", messageDigestAlgo);
		return new DigestCalculator() {

			@Override
			public OutputStream getOutputStream() {
				OutputStream os = new ByteArrayOutputStream();
				try {
					Utils.write(getDigest(), os);
				} catch (IOException e) {
					throw new DSSException("Unable to get outputstream", e);
				}
				return os;
			}

			@Override
			public byte[] getDigest() {
				return Utils.fromBase64(messageDigestValueBase64);
			}

			@Override
			public AlgorithmIdentifier getAlgorithmIdentifier() {
				return new AlgorithmIdentifier(new ASN1ObjectIdentifier(messageDigestAlgo.getOid()));
			}

		};
	}

}
