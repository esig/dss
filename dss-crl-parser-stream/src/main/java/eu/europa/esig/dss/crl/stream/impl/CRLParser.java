/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.crl.stream.impl;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertList.CRLEntry;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.jce.provider.X509CRLEntryObject;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.X509CRLEntry;
import java.util.Enumeration;

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
	 * This method extracts the signed data (TBSCertList)
	 * 
	 * @param is
	 *          {@link BinaryFilteringInputStream} an initialized CRLSignedDataInputStream
	 * @throws IOException if an error occurs during the InputStream reading
	 */
	public void getSignedData(BinaryFilteringInputStream is) throws IOException {
		// We don't digest the beginning (not part of TBS)
		is.on(false);

		// Skip CertificateList Sequence info
		consumeTagIntro(is);

		// Start to digest TBS
		is.on(true);

		// Strip the tag and length of the TBSCertList sequence
		int tag = DERUtil.readTag(is);
		DERUtil.readTagNumber(is, tag);
		int tbsLength = DERUtil.readLength(is);

		// Read TBSCertList Content
		readNbBytes(is, tbsLength);

		// End digest TBS
		is.on(false);
	}

	/**
	 * This method allows to parse the CRL and return the revocation data for a given serial number
	 * 
	 * @param is
	 *            {@link InputStream} an InputStream with the CRL
	 * @param serialNumber
	 *            {@link BigInteger} the certificate's serial number
	 * @return {@link X509CRLEntry} with the revocation date, the reason,... or null if the serial number is not present in
	 *         the CRL
	 * @throws IOException if an exception occurs
	 */
	public X509CRLEntry retrieveRevocationInfo(InputStream is, BigInteger serialNumber) throws IOException {
		// Skip CertificateList Sequence info
		consumeTagIntro(is);

		// Read TBSCertList Sequence
		consumeTagIntro(is);

		// Skip all before mandatory thisUpdate
		int tag = -1;
		int tagNo = BERTags.NULL;
		int length = -1;
		do {
			tag = DERUtil.readTag(is);
			tagNo = DERUtil.readTagNumber(is, tag);
			length = DERUtil.readLength(is);
			skip(is, length);
		} while (!isDate(tagNo));

		tag = DERUtil.readTag(is);
		tagNo = DERUtil.readTagNumber(is, tag);
		length = DERUtil.readLength(is);

		// TBSCertList -> nextUpdate (optional)
		if (isDate(tagNo)) {
			skip(is, length);

			tag = DERUtil.readTag(is);
			tagNo = DERUtil.readTagNumber(is, tag);
			length = DERUtil.readLength(is);
		}

		while (tagNo == BERTags.SEQUENCE) {
			tag = DERUtil.readTag(is);

			if (tag < 0) {
				// EOF
				return null;
			}

			tagNo = DERUtil.readTagNumber(is, tag);
			length = DERUtil.readLength(is);

			if (tagNo == BERTags.SEQUENCE) {

				byte[] entryArray = readNbBytes(is, length);

				try (InputStream bais = new ByteArrayInputStream(entryArray)) {
					int entryTag = DERUtil.readTag(bais);
					int entryTagNo = DERUtil.readTagNumber(bais, entryTag);
					int entryLength = DERUtil.readLength(bais);

					// SerialNumber
					if (BERTags.INTEGER == entryTagNo) {
						ASN1Integer asn1SerialNumber = rebuildASN1Integer(readNbBytes(bais, entryLength));
						if (serialNumber.equals(asn1SerialNumber.getValue())) {
							ASN1Sequence asn1Sequence = rebuildASN1Sequence(entryArray);
							CRLEntry crlEntry = CRLEntry.getInstance(asn1Sequence);
							return new X509CRLEntryObject(crlEntry);
						}
					}
				}
			} else {
				LOG.debug("Should only contain SEQUENCEs : tagNo = {} (ignored)", tagNo);
				skip(is, length);
			}
		}

		return null;
	}

	/**
	 * This method allows to retrieve common CRL information (thisUpdate, nextUpdate, signatureAlgorithm,
	 * signatureValue, extensions,...). It voluntary doesn't parse the revokedCertificates sequence.
	 * 
	 * @param is
	 *            an instance of {@link InputStream} with the CRL. The InputStream MUST support mark()/reset() methods.
	 * 
	 * @return a DTO with extracted infos
	 * @throws IOException if an exception occurs
	 */
	public CRLInfo retrieveInfo(InputStream is) throws IOException {

		if (!is.markSupported()) {
			throw new IllegalArgumentException("The InputStream MUST support mark/reset methods !");
		}

		CRLInfo infos = new CRLInfo();

		// Skip CertificateList Sequence info
		consumeTagIntro(is);

		// Read TBSCertList Sequence
		consumeTagIntro(is);

		int tag = DERUtil.readTag(is);
		int tagNo = DERUtil.readTagNumber(is, tag);
		int length = DERUtil.readLength(is);

		// TBSCertList -> version (optional)
		if (tagNo == BERTags.INTEGER) {
			byte[] array = readNbBytes(is, length);
			if (LOG.isDebugEnabled()) {
				LOG.debug("TBSCertList -> version : {}", Hex.toHexString(array));
			}
			infos.setVersion(rebuildASN1Integer(array).getValue().intValue() + 1);

			tag = DERUtil.readTag(is);
			tagNo = DERUtil.readTagNumber(is, tag);
			length = DERUtil.readLength(is);
		}

		// TBSCertList -> signature
		if (tagNo == BERTags.SEQUENCE) {
			byte[] array = readNbBytes(is, length);
			if (LOG.isDebugEnabled()) {
				LOG.debug("TBSCertList -> signatureAlgorithm : {}", Hex.toHexString(array));
			}
			AlgorithmIdentifier algoId = AlgorithmIdentifier.getInstance(rebuildASN1Sequence(array));
			ASN1ObjectIdentifier oid = algoId.getAlgorithm();
			infos.setCertificateListSignatureAlgorithmOid(oid.getId());
			ASN1Encodable parameters = algoId.getParameters();
			if (parameters != null && !DERNull.INSTANCE.equals(parameters)) {
				infos.setCertificateListSignatureAlgorithmParams(parameters.toASN1Primitive().getEncoded(ASN1Encoding.DER));
			}

			tag = DERUtil.readTag(is);
			tagNo = DERUtil.readTagNumber(is, tag);
			length = DERUtil.readLength(is);
		}

		// TBSCertList -> issuer
		if (tagNo == BERTags.SEQUENCE) {
			byte[] array = readNbBytes(is, length);
			if (LOG.isDebugEnabled()) {
				LOG.debug("TBSCertList -> issuer : {}", Hex.toHexString(array));
			}
			ASN1Sequence sequence = rebuildASN1Sequence(array);
			infos.setIssuer(new X500Principal(sequence.getEncoded()));

			tag = DERUtil.readTag(is);
			tagNo = DERUtil.readTagNumber(is, tag);
			length = DERUtil.readLength(is);
		}

		// TBSCertList -> thisUpdate
		if (isDate(tagNo)) {
			byte[] array = readNbBytes(is, length);
			if (LOG.isDebugEnabled()) {
				LOG.debug("TBSCertList -> thisUpdate : {}", Hex.toHexString(array));
			}
			Time time = rebuildASN1Time(tagNo, array);
			infos.setThisUpdate(time.getDate());

			tag = DERUtil.readTag(is);
			tagNo = DERUtil.readTagNumber(is, tag);
			length = DERUtil.readLength(is);
		}

		// TBSCertList -> nextUpdate (optional)
		if (isDate(tagNo)) {
			byte[] array = readNbBytes(is, length);
			if (LOG.isDebugEnabled()) {
				LOG.debug("TBSCertList -> nextUpdate : {}", Hex.toHexString(array));
			}
			Time time = rebuildASN1Time(tagNo, array);
			infos.setNextUpdate(time.getDate());

			tag = DERUtil.readTag(is);
			tagNo = DERUtil.readTagNumber(is, tag);
			length = DERUtil.readLength(is);
		}

		// TBSCertList -> revokedCertificates (optional)
		if (tagNo == BERTags.SEQUENCE) {
			// process data only if this sequence contains any data
			if (length > 0) {
				// TODO find a way to avoid mark/reset
				is.mark(10);
				int intraTag = DERUtil.readTag(is);
				int intraTagNo = DERUtil.readTagNumber(is, intraTag);
				is.reset();

				// If sequence of sequence -> revokedCertificates else CertificateList -> signatureAlgorithm
				if (intraTagNo == BERTags.SEQUENCE) {

					// Don't parse revokedCertificates
					skip(is, length);
					LOG.debug("TBSCertList -> revokedCertificates : skipped (length={})", length);

					tag = DERUtil.readTag(is);
					tagNo = DERUtil.readTagNumber(is, tag);
					length = DERUtil.readLength(is);
				}
			} else {

				LOG.debug("TBSCertList -> revokedCertificates : Empty sequence");
				
				// even if the sequence is empty we must prepare for the next sequence to be read
				tag = DERUtil.readTag(is);
				tagNo = DERUtil.readTagNumber(is, tag);
				length = DERUtil.readLength(is);
			}
		}

		boolean isTagged = (tag & BERTags.TAGGED) != 0;

		// TBSCertList -> crlExtensions
		if (isTagged) {
			byte[] array = readNbBytes(is, length);
			if (LOG.isDebugEnabled()) {
				LOG.debug("TBSCertList -> crlExtensions : {}", Hex.toHexString(array));
			}

			ASN1Sequence sequenceExtensions = (ASN1Sequence) ASN1Primitive.fromByteArray(array);
			extractExtensions(sequenceExtensions, infos);

			tag = DERUtil.readTag(is);
			tagNo = DERUtil.readTagNumber(is, tag);
			length = DERUtil.readLength(is);
		}

		// CertificateList -> signatureAlgorithm
		if (BERTags.SEQUENCE == tagNo) {
			byte[] array = readNbBytes(is, length);
			if (LOG.isDebugEnabled()) {
				LOG.debug("CertificateList -> signatureAlgorithm : {}", Hex.toHexString(array));
			}

			AlgorithmIdentifier algoId = AlgorithmIdentifier.getInstance(rebuildASN1Sequence(array));
			infos.setTbsSignatureAlgorithmOid(algoId.getAlgorithm().getId());

			tag = DERUtil.readTag(is);
			tagNo = DERUtil.readTagNumber(is, tag);
			length = DERUtil.readLength(is);
		}

		// CertificateList -> signatureValue
		if (BERTags.BIT_STRING == tagNo) {
			byte[] array = readNbBytes(is, length);
			if (LOG.isDebugEnabled()) {
				LOG.debug("CertificateList -> signatureValue : {}", Hex.toHexString(array));
			}
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
	 * @param is
	 *            {@link InputStream}
	 * @param length
	 *            number of bytes to be skipped
	 * @throws IOException if an error occurs during the InputStream reading
	 */
	private void skip(InputStream is, int length) throws IOException {
		long skipped = 0;
		long skip = -1;
		// Loops because BufferedInputStream.skip only skips in its buffer
		while (skipped < length && skip != 0) {
			skip = is.skip(length - skipped);
			skipped += skip;
		}
	}

	private void extractExtensions(ASN1Sequence seq, CRLInfo info) throws IOException {
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
					info.addNonCriticalExtension(oid.getId(), content);
				} else if (seqSize == 3) {
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) extension.getObjectAt(0);
					ASN1Boolean isCritical = (ASN1Boolean) extension.getObjectAt(1);
					byte[] content = extension.getObjectAt(2).toASN1Primitive().getEncoded();
					if (isCritical.isTrue()) {
						info.addCriticalExtension(oid.getId(), content);
					} else {
						info.addNonCriticalExtension(oid.getId(), content);
					}
				} else {
					LOG.warn("Not supported format : {}", extension);
				}
			} catch (Exception e) {
				LOG.warn("Cannot parse extension {} : {}", extension, e.getMessage());
			}
		}
	}

	/**
	 * This method reads the tag and content length
	 * 
	 * @param is
	 *            {@link InputStream}
	 * @throws IOException if an exception occurs
	 */
	private void consumeTagIntro(InputStream is) throws IOException {
		int tag = DERUtil.readTag(is);
		DERUtil.readTagNumber(is, tag);
		DERUtil.readLength(is);
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
