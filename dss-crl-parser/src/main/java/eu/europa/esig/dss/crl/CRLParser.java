package eu.europa.esig.dss.crl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.crl.handler.SignatureEventHandler;
import eu.europa.esig.dss.crl.handler.ToBeSignedEventHandler;

/**
 * http://luca.ntop.org/Teaching/Appunti/asn1.html
 * 
 * <pre>
 * {@code
 * CertificateList  ::=  SEQUENCE  {
 *      tbsCertList          TBSCertList,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signatureValue       BIT STRING  }
 *
 * TBSCertList  ::=  SEQUENCE  {
 *      version                 Version OPTIONAL,
 *                                   -- if present, MUST be v2
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      thisUpdate              Time,
 *      nextUpdate              Time OPTIONAL,
 *      revokedCertificates     SEQUENCE OF SEQUENCE  {
 *           userCertificate         CertificateSerialNumber,
 *           revocationDate          Time,
 *           crlEntryExtensions      Extensions OPTIONAL
 *                                    -- if present, version MUST be v2
 *                                }  OPTIONAL,
 *      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                    -- if present, version MUST be v2
 *                                }
 *
 * Version, Time, CertificateSerialNumber, and Extensions
 * are all defined in the ASN.1 in Section 4.1
 *
 * AlgorithmIdentifier is defined in Section 4.1.1.2
 * }
 * </pre>
 */
public class CRLParser {

	private static final Logger LOG = LoggerFactory.getLogger(CRLParser.class);

	public void processDigest(InputStream s, ToBeSignedEventHandler handler) throws IOException {

		// Strip the tag and length of the CertificateList sequence
		int tag = DERUtil.readTag(s);
		DERUtil.readTagNumber(s, tag);
		DERUtil.readLength(s);

		handler.beforeTbs();

		readTBSCertList(s);

		handler.afterTbs();
	}

	public void retrieveSignatureInfo(InputStream s, SignatureEventHandler handler) throws IOException {
		// Strip the tag and length of the CertificateList sequence
		int tag = DERUtil.readTag(s);
		DERUtil.readTagNumber(s, tag);
		DERUtil.readLength(s);

		readTBSCertList(s);

		ASN1ObjectIdentifier oid = readSignatureAlgorithm(s);
		handler.onSignatureAlgorithm(oid);

	}

	private void readTBSCertList(InputStream s) throws IOException {
		// Strip the tag and length of the TBSCertList sequence
		int tag = DERUtil.readTag(s);
		DERUtil.readTagNumber(s, tag);

		// Read TBSCertList Content
		int tbsLength = DERUtil.readLength(s);
		byte[] array = new byte[tbsLength];
		if (Streams.readFully(s, array) != tbsLength) {
			LOG.warn("TBS is not fully read !");
		}
	}

	private ASN1ObjectIdentifier readSignatureAlgorithm(InputStream s) throws IOException {

		int tag = DERUtil.readTag(s);
		int tagNo = DERUtil.readTagNumber(s, tag);
		if (BERTags.SEQUENCE == tagNo) {

			int signatureAlgorithmLength = DERUtil.readLength(s);
			byte[] array = new byte[signatureAlgorithmLength];
			if (Streams.readFully(s, array) != signatureAlgorithmLength) {
				LOG.warn("SignatureAlgorithm is not fully read !");
			}

			ASN1Sequence asn1Sequence = rebuildASN1Sequence(array);
			return (ASN1ObjectIdentifier) asn1Sequence.getObjectAt(0);
		}
		return null;
	}

	private ASN1Sequence rebuildASN1Sequence(byte[] array) throws IOException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			baos.write(0x30);
			DERUtil.writeLength(baos, array.length);
			baos.write(array);
			return (ASN1Sequence) ASN1Sequence.fromByteArray(baos.toByteArray());
		}
	}

}
