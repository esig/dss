package eu.europa.ec.markt.dss.mock;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

public class MockTSPSource implements TSPSource {

	private static final long serialVersionUID = 9003417203772249074L;

	private static final Logger LOG = LoggerFactory.getLogger(MockTSPSource.class);

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private Date lastTimestampDate = null;

	private ASN1ObjectIdentifier policyOid;

	private final PrivateKey key;

	private final CertificateToken cert;

	private final Date timestampDate;

	/**
	 * The default constructor for MockTSPSource.
	 *
	 */
	public MockTSPSource(final DSSPrivateKeyEntry entry, final Date timestampDate) throws DSSException {
		this.timestampDate = timestampDate;

		key = entry.getPrivateKey();
		cert = entry.getCertificate();

		this.setPolicyOid("1.234.567.890");

		LOG.debug("TSP mockup with certificate {}", cert.getDSSId());

	}

	@Override
	public TimeStampToken getTimeStampResponse(final DigestAlgorithm digestAlgorithm, final byte[] digest) throws DSSException {

		final String signatureAlgorithm = getSignatureAlgorithm(digestAlgorithm, digest);

		final TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
		tsqGenerator.setCertReq(true);
		/**
		 * The code below guarantee that the dates of the two successive
		 * timestamps are different.
		 */
		if (lastTimestampDate == null) {
			lastTimestampDate = timestampDate;
		} else {

			final long time = lastTimestampDate.getTime() + 1000;
			lastTimestampDate = new Date(time);
		}
		final Date timestampDate_ = lastTimestampDate;
		LOG.debug("-->#######:O:" + timestampDate.toString());
		LOG.debug("-->#######:N:" + timestampDate_.toString());
		final BigInteger nonce = BigInteger.valueOf(timestampDate.getTime());
		final TimeStampRequest tsRequest = tsqGenerator.generate(digestAlgorithm.getOid(), digest, nonce);
		if (policyOid != null) {

			tsqGenerator.setReqPolicy(policyOid);
		}

		try {
			final ContentSigner sigGen = new JcaContentSignerBuilder(signatureAlgorithm).build(key);
			final JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(cert.getCertificate());

			// that to make sure we generate the same timestamp data for the
			// same timestamp date
			AttributeTable signedAttributes = new AttributeTable(new Hashtable());
			signedAttributes = signedAttributes.add(PKCSObjectIdentifiers.pkcs_9_at_signingTime, new Time(timestampDate_));
			final DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributes);
			AttributeTable unsignedAttributes = new AttributeTable(new Hashtable());
			final SimpleAttributeTableGenerator unsignedAttributeGenerator = new SimpleAttributeTableGenerator(unsignedAttributes);

			final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();
			SignerInfoGeneratorBuilder sigInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);
			sigInfoGeneratorBuilder.setSignedAttributeGenerator(signedAttributeGenerator);
			sigInfoGeneratorBuilder.setUnsignedAttributeGenerator(unsignedAttributeGenerator);
			final SignerInfoGenerator sig = sigInfoGeneratorBuilder.build(sigGen, certHolder);

			final DigestCalculator sha1DigestCalculator = DSSUtils.getSHA1DigestCalculator();

			final TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(sig, sha1DigestCalculator, policyOid);
			final Set<X509Certificate> singleton = new HashSet<X509Certificate>();
			singleton.add(cert.getCertificate());
			tokenGenerator.addCertificates(new JcaCertStore(singleton));
			final TimeStampResponseGenerator generator = new TimeStampResponseGenerator(tokenGenerator, TSPAlgorithms.ALLOWED);

			TimeStampResponse tsResponse = generator.generate(tsRequest, BigInteger.ONE, timestampDate_);
			final TimeStampToken timeStampToken = tsResponse.getTimeStampToken();
			return timeStampToken;
		} catch (OperatorCreationException e) {
			throw new DSSException(e);
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		} catch (TSPException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public void setPolicyOid(final String policyOid) {
		this.policyOid = new ASN1ObjectIdentifier(policyOid);
	}

	@Override
	public String getUniqueId(byte[] digestValue) {
		final byte[] digest = DSSUtils.digest(DigestAlgorithm.MD5, digestValue, DSSUtils.toByteArray(timestampDate.getTime()));
		return Hex.encodeHexString(digest);
	}

	private String getSignatureAlgorithm(DigestAlgorithm algorithm, byte[] digest) {

		String signatureAlgorithm;
		if (DigestAlgorithm.SHA1.equals(algorithm)) {
			signatureAlgorithm = "SHA1withRSA";
			if (digest.length != 20) {
				throw new IllegalArgumentException("Not valid size for a SHA1 digest : " + digest.length + " bytes");
			}
		} else if (DigestAlgorithm.SHA256.equals(algorithm)) {
			signatureAlgorithm = "SHA256withRSA";
			if (digest.length != 32) {
				throw new IllegalArgumentException("Not valid size for a SHA256 digest : " + digest.length + " bytes");
			}
		} else {

			throw new UnsupportedOperationException("No support for " + algorithm);
		}
		return signatureAlgorithm;
	}

}
