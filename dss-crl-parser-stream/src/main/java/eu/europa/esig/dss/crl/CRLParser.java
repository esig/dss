package eu.europa.esig.dss.crl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.cert.X509CRLEntry;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.x509.TBSCertList.CRLEntry;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.jce.provider.X509CRLEntryObject;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
class CRLParser {

	private static final Logger LOG = LoggerFactory.getLogger(CRLParser.class);

	/**
	 * This method allows to compute the digest of the TBSCertList
	 * 
	 * @param s
	 *            an initialized DigestInputStream
	 * @throws IOException
	 */
	public void processDigest(DigestInputStream s) throws IOException {

		// We don't digest the beginning (not part of TBS)
		s.on(false);

		// Skip CertificateList Sequence info
		consumeTagIntro(s);

		// Start to digest TBS
		s.on(true);

		// Strip the tag and length of the TBSCertList sequence
		int tag = DERUtil.readTag(s);
		DERUtil.readTagNumber(s, tag);
		int tbsLength = DERUtil.readLength(s);

		// Read TBSCertList Content
		readNbBytes(s, tbsLength);

		// End digest TBS
		s.on(false);
	}

	/**
	 * This method allows to parse the CRL and return the revocation data for a given serial number
	 * 
	 * @param s
	 *            an InputStream with the CRL
	 * @param serialNumber
	 *            the certificate's serial number
	 * @return the X509CRLEntry with the revocation date, the reason,... or null if the serial number is not present in
	 *         the CRL
	 * @throws IOException
	 */
	public X509CRLEntry retrieveRevocationInfo(InputStream s, BigInteger serialNumber) throws IOException {
		// Skip CertificateList Sequence info
		consumeTagIntro(s);

		// Read TBSCertList Sequence
		consumeTagIntro(s);

		// Skip all before mandatory thisUpdate
		int tag = -1;
		int tagNo = BERTags.NULL;
		int length = -1;
		do {
			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
			skip(s, length);
		} while (!isDate(tagNo));

		tag = DERUtil.readTag(s);
		tagNo = DERUtil.readTagNumber(s, tag);
		length = DERUtil.readLength(s);

		// TBSCertList -> nextUpdate (optional)
		if (isDate(tagNo)) {
			skip(s, length);

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		if (tagNo == BERTags.SEQUENCE) {

			while (true) {
				tag = DERUtil.readTag(s);

				if (tag < 0) {
					// EOF
					return null;
				}

				tagNo = DERUtil.readTagNumber(s, tag);
				length = DERUtil.readLength(s);

				if (tagNo == BERTags.SEQUENCE) {

					byte[] entryArray = readNbBytes(s, length);

					try (InputStream is = new ByteArrayInputStream(entryArray)) {
						int entryTag = DERUtil.readTag(is);
						int entryTagNo = DERUtil.readTagNumber(is, entryTag);
						int entryLength = DERUtil.readLength(is);

						// SerialNumber
						if (BERTags.INTEGER == entryTagNo) {
							ASN1Integer asn1SerialNumber = rebuildASN1Integer(readNbBytes(is, entryLength));
							if (serialNumber.equals(asn1SerialNumber.getValue())) {
								ASN1Sequence asn1Sequence = rebuildASN1Sequence(entryArray);
								CRLEntry crlEntry = CRLEntry.getInstance(asn1Sequence);
								return new X509CRLEntryObject(crlEntry);
							}
						}
					}
				} else {
					LOG.debug("Should only contain SEQUENCEs : tagNo = {} (ignored)", tagNo);
					skip(s, length);
				}
			}
		}
		return null;
	}

	/**
	 * This method allows to retrieve common CRL informations (thisUpdate, nextUpdate, signatureAlgorithm,
	 * signatureValue, extensions,...). It voluntary doesn't parse the revokedCertificates sequence.
	 * 
	 * @param s
	 *            an instance of InputStream with the CRL. The InputStream MUST support mark()/reset() methods.
	 * 
	 * @return a DTO with extracted infos
	 * @throws IOException
	 */
	public CRLInfo retrieveInfo(InputStream s) throws IOException {

		if (!s.markSupported()) {
			throw new IllegalArgumentException("The InputStream MUST support mark/reset methods !");
		}

		CRLInfo infos = new CRLInfo();

		// Skip CertificateList Sequence info
		consumeTagIntro(s);

		// Read TBSCertList Sequence
		consumeTagIntro(s);

		int tag = DERUtil.readTag(s);
		int tagNo = DERUtil.readTagNumber(s, tag);
		int length = DERUtil.readLength(s);

		// TBSCertList -> version (optional)
		if (tagNo == BERTags.INTEGER) {
			byte[] array = readNbBytes(s, length);
			LOG.debug("TBSCertList -> version : {}", Hex.toHexString(array));
			infos.setVersion(rebuildASN1Integer(array).getValue().intValue() + 1);

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// TBSCertList -> signature
		if (tagNo == BERTags.SEQUENCE) {
			byte[] array = readNbBytes(s, length);
			LOG.debug("TBSCertList -> signatureAlgorithm : {}", Hex.toHexString(array));
			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) rebuildASN1Sequence(array).getObjectAt(0);
			infos.setCertificateListSignatureAlgorithmOid(oid.getId());

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// TBSCertList -> issuer
		if (tagNo == BERTags.SEQUENCE) {
			byte[] array = readNbBytes(s, length);
			LOG.debug("TBSCertList -> issuer : {}", Hex.toHexString(array));
			ASN1Sequence sequence = rebuildASN1Sequence(array);
			infos.setIssuer(new X500Principal(sequence.getEncoded()));

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// TBSCertList -> thisUpdate
		if (isDate(tagNo)) {
			byte[] array = readNbBytes(s, length);
			LOG.debug("TBSCertList -> thisUpdate : {}", Hex.toHexString(array));
			Time time = rebuildASN1Time(tagNo, array);
			infos.setThisUpdate(time.getDate());

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// TBSCertList -> nextUpdate (optional)
		if (isDate(tagNo)) {
			byte[] array = readNbBytes(s, length);
			LOG.debug("TBSCertList -> nextUpdate : {}", Hex.toHexString(array));
			Time time = rebuildASN1Time(tagNo, array);
			infos.setNextUpdate(time.getDate());

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// TBSCertList -> revokedCertificates (optional)
		if (tagNo == BERTags.SEQUENCE) {
			// process data only if this sequence contains any data
			if (length > 0) {
				// TODO find a way to avoid mark/reset
				s.mark(10);
				int intraTag = DERUtil.readTag(s);
				int intraTagNo = DERUtil.readTagNumber(s, intraTag);
				s.reset();

				// If sequence of sequence -> revokedCertificates else CertificateList -> signatureAlgorithm
				if (intraTagNo == BERTags.SEQUENCE) {

					// Don't parse revokedCertificates
					skip(s, length);
					LOG.debug("TBSCertList -> revokedCertificates : skipped (length={})", length);

					tag = DERUtil.readTag(s);
					tagNo = DERUtil.readTagNumber(s, tag);
					length = DERUtil.readLength(s);
				}
			} else {
				LOG.debug("TBSCertList -> revokedCertificates : Empty sequence");
				
				// even if the sequence is empty we must prepare for the next sequence to be read
				tag = DERUtil.readTag(s);
				tagNo = DERUtil.readTagNumber(s, tag);
				length = DERUtil.readLength(s);
			}
		}

		boolean isTagged = (tag & BERTags.TAGGED) != 0;

		// TBSCertList -> crlExtensions
		if (isTagged) {
			byte[] array = readNbBytes(s, length);
			LOG.debug("TBSCertList -> crlExtensions : {}", Hex.toHexString(array));

			ASN1Sequence sequenceExtensions = (ASN1Sequence) ASN1Sequence.fromByteArray(array);
			extractExtensions(sequenceExtensions, infos);

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// CertificateList -> signatureAlgorithm
		if (BERTags.SEQUENCE == tagNo) {
			byte[] array = readNbBytes(s, length);
			LOG.debug("CertificateList -> signatureAlgorithm : {}", Hex.toHexString(array));

			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) rebuildASN1Sequence(array).getObjectAt(0);
			infos.setTbsSignatureAlgorithmOid(oid.getId());

			tag = DERUtil.readTag(s);
			tagNo = DERUtil.readTagNumber(s, tag);
			length = DERUtil.readLength(s);
		}

		// CertificateList -> signatureValue
		if (BERTags.BIT_STRING == tagNo) {
			byte[] array = readNbBytes(s, length);
			LOG.debug("CertificateList -> signatureValue : {}", Hex.toHexString(array));
			infos.setSignatureValue(rebuildASN1BitString(array).getOctets());
		}

		return infos;
	}

	private boolean isDate(int tagNo) {
		return (tagNo == BERTags.UTC_TIME) || (tagNo == BERTags.GENERALIZED_TIME);
	}

	private byte[] readNbBytes(InputStream s, int length) throws IOException {
		byte[] array = new byte[length];
		if (Streams.readFully(s, array) != length) {
			LOG.warn("Cannot read expected length!");
		}
		return array;
	}

	/**
	 * This method skips n bytes in the InputStream
	 * 
	 * @param s
	 *            the InputStream
	 * @param n
	 *            number of bytes to be skipped
	 * @throws IOException
	 */
	private void skip(InputStream s, int length) throws IOException {
		int skipped = 0;
		// Loops because BufferedInputStream.skip only skips in its buffer
		while (skipped < length) {
			skipped += s.skip(length - skipped);
		}
	}

	private void extractExtensions(ASN1Sequence seq, CRLInfo infos) throws IOException {
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
					infos.addNonCriticalExtension(oid.getId(), content);
				} else if (seqSize == 3) {
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) extension.getObjectAt(0);
					ASN1Boolean isCritical = (ASN1Boolean) extension.getObjectAt(1);
					byte[] content = extension.getObjectAt(2).toASN1Primitive().getEncoded();
					if (isCritical.isTrue()) {
						infos.addCriticalExtension(oid.getId(), content);
					} else {
						infos.addNonCriticalExtension(oid.getId(), content);
					}
				} else {
					LOG.warn("Not supported format : {}", extension);
				}
			} catch (Exception e) {
				LOG.warn("Cannot parse extension : {}", extension, e.getMessage());
			}
		}
	}

	/**
	 * This method reads the tag and content length
	 * 
	 * @param s
	 *            the InputStream
	 * @throws IOException
	 */
	private void consumeTagIntro(InputStream s) throws IOException {
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
