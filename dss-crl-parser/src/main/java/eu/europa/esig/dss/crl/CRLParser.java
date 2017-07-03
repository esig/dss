package eu.europa.esig.dss.crl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.crl.handler.CRLInfoEventHandler;
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

		// Skip CertificateList Sequence info
		skipTagIntro(s);

		handler.beforeTbs();

		readTBSCertList(s);

		handler.afterTbs();
	}

	public void retrieveInfo(InputStream s, CRLInfoEventHandler handler) throws IOException {
		// Skip CertificateList Sequence info
		skipTagIntro(s);

		// Read TBSCertList Sequence
		int tag = DERUtil.readTag(s);
		int tagNo = DERUtil.readTagNumber(s, tag);
		int length = DERUtil.readLength(s);

		tag = DERUtil.readTag(s);
		tagNo = DERUtil.readTagNumber(s, tag);
		length = DERUtil.readLength(s);

		// version (optional)
		if (tagNo == BERTags.INTEGER) {
			byte[] array = new byte[length];
			if (Streams.readFully(s, array) != length) {
				LOG.warn("Version is not fully read !");
			}
			handler.onVersion(rebuildASN1Integer(array).getValue().intValue());

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// signature
		if (tagNo == BERTags.SEQUENCE) {
			byte[] array = new byte[length];
			if (Streams.readFully(s, array) != length) {
				LOG.warn("signature is not fully read !");
			}
			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) rebuildASN1Sequence(array).getObjectAt(0);
			handler.onCertificateListSignatureAlgorithm(SignatureAlgorithm.forOID(oid.getId()));

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// issuer
		if (tagNo == BERTags.SEQUENCE) {
			byte[] array = new byte[length];
			if (Streams.readFully(s, array) != length) {
				LOG.warn("issuer is not fully read !");
			}
			ASN1Sequence sequence = rebuildASN1Sequence(array);
			handler.onIssuer(new X500Principal(sequence.getEncoded()));

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// thisUpdate
		if (tagNo == BERTags.UTC_TIME || tagNo == BERTags.GENERALIZED_TIME) {
			byte[] array = new byte[length];
			if (Streams.readFully(s, array) != length) {
				LOG.warn("thisUpdate is not fully read !");
			}
			Time time = rebuildASN1Time(tagNo, array);
			handler.onThisUpdate(time.getDate());

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// nextUpdate (optional)
		if (tagNo == BERTags.UTC_TIME || tagNo == BERTags.GENERALIZED_TIME) {
			byte[] array = new byte[length];
			if (Streams.readFully(s, array) != length) {
				LOG.warn("nextUpdate is not fully read !");
			}
			Time time = rebuildASN1Time(tagNo, array);
			handler.onNextUpdate(time.getDate());

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// revokedCertificates (optional)
		if (tagNo == BERTags.SEQUENCE) {

			s.mark(10);
			int intraTag = DERUtil.readTag(s);
			int intraTagNo = DERUtil.readTagNumber(s, intraTag);
			s.reset();

			if (intraTagNo == BERTags.SEQUENCE) {

				// Don't parse revokedCertificates
				s.skip(length);

				tag = DERUtil.readTag(s);
				tagNo = DERUtil.readTagNumber(s, tag);
				length = DERUtil.readLength(s);
			}
		}

		boolean isTagged = (tag & BERTags.TAGGED) != 0;

		// crlExtensions
		if (isTagged) {

			byte[] array = new byte[length];
			if (Streams.readFully(s, array) != length) {
				LOG.warn("crlExtensions is not fully read !");
			}

			extractExtensions(rebuildASN1Sequence(array), handler);

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// CertificateList -> signatureAlgorithm
		if (BERTags.SEQUENCE == tagNo) {
			byte[] array = new byte[length];
			if (Streams.readFully(s, array) != length) {
				LOG.warn("SignatureAlgorithm is not fully read !");
			}

			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) rebuildASN1Sequence(array).getObjectAt(0);
			handler.onTbsSignatureAlgorithm(SignatureAlgorithm.forOID(oid.getId()));

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// CertificateList -> signatureValue
		if (BERTags.BIT_STRING == tagNo) {
			byte[] array = new byte[length];
			if (Streams.readFully(s, array) != length) {
				LOG.warn("SignatureValue is not fully read !");
			}
			handler.onSignatureValue(rebuildASN1BitString(array).getOctets());
		}
	}

	private void extractExtensions(ASN1Sequence seq, CRLInfoEventHandler handler) throws IOException {
		@SuppressWarnings("rawtypes")
		Enumeration enumSeq = seq.getObjects();
		while (enumSeq.hasMoreElements()) {
			ASN1Sequence extension = null;
			try {
				extension = (ASN1Sequence) enumSeq.nextElement();
				int seqSize = extension.size();
				if (seqSize == 2) {
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) extension.getObjectAt(0);
					byte[] content = extension.getObjectAt(1).toASN1Primitive().getEncoded();
					handler.onNonCriticalExtension(oid.getId(), content);
				} else if (seqSize == 3) {
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) extension.getObjectAt(0);
					ASN1Boolean isCritical = (ASN1Boolean) extension.getObjectAt(1);
					byte[] content = extension.getObjectAt(2).toASN1Primitive().getEncoded();
					if (isCritical.isTrue()) {
						handler.onCriticalExtension(oid.getId(), content);
					} else {
						handler.onNonCriticalExtension(oid.getId(), content);
					}
				} else {
					LOG.warn("Not supported format : {}", extension);
				}
			} catch (Exception e) {
				LOG.error("Cannot parser extension : {}", extension, e.getMessage());
			}
		}
	}

	private void readTBSCertList(InputStream s) throws IOException {
		// Strip the tag and length of the TBSCertList sequence
		int tag = DERUtil.readTag(s);
		DERUtil.readTagNumber(s, tag);
		int tbsLength = DERUtil.readLength(s);

		// Read TBSCertList Content
		byte[] array = new byte[tbsLength];
		if (Streams.readFully(s, array) != tbsLength) {
			LOG.warn("TBS is not fully read !");
		}
	}

	private void skipTagIntro(InputStream s) throws IOException {
		int tag = DERUtil.readTag(s);
		DERUtil.readTagNumber(s, tag);
		DERUtil.readLength(s);
	}

	private ASN1Sequence rebuildASN1Sequence(byte[] array) throws IOException {
		// BERTags.SEQUENCE | BERTags.CONSTRUCTED = 0x30
		return (ASN1Sequence) rebuildASN1Primitive((BERTags.SEQUENCE | BERTags.CONSTRUCTED), array);
	}

	private ASN1BitString rebuildASN1BitString(byte[] array) throws IOException {
		return (ASN1BitString) rebuildASN1Primitive(BERTags.BIT_STRING, array);
	}

	private ASN1Integer rebuildASN1Integer(byte[] array) throws IOException {
		return (ASN1Integer) rebuildASN1Primitive(BERTags.INTEGER, array);
	}

	private Time rebuildASN1Time(int tagNo, byte[] array) throws IOException {
		// Tag UTC or GeneralizedTime
		return Time.getInstance(rebuildASN1Primitive(tagNo, array));
	}

	private ASN1Primitive rebuildASN1Primitive(int tagNo, byte[] array) throws IOException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			baos.write(tagNo);
			DERUtil.writeLength(baos, array.length);
			baos.write(array);
			return ASN1Primitive.fromByteArray(baos.toByteArray());
		}
	}

}
