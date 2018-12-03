/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.x509.CertificateToken;

public class InfiniteLoopDSS621Test {

	private static final Logger logger = LoggerFactory.getLogger(InfiniteLoopDSS621Test.class);

	private static final String FILE_PATH = "/validation/pades-5-signatures-and-1-document-timestamp.pdf";

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test(timeout = 5000)
	public void testReadTimestamp1() throws Exception {
		DSSDocument signDocument = new InMemoryDocument(getClass().getResourceAsStream(FILE_PATH));
		final CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setDataLoader(new IgnoreDataLoader()); // Error 404 on DER policy

		final SignedDocumentValidator signedDocumentValidator = SignedDocumentValidator.fromDocument(signDocument);
		signedDocumentValidator.setCertificateVerifier(certificateVerifier);
		Reports reports = signedDocumentValidator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();

		assertEquals(5, signatures.size()); // 1 timestamp is not counted as signature
		for (final SignatureWrapper signature : signatures) {
			List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
			for (XmlDigestMatcher digestMatcher : digestMatchers) {
				assertTrue(digestMatcher.isDataFound());
				assertTrue(digestMatcher.isDataIntact());
			}

			assertFalse(signature.isSignatureIntact());
			assertFalse(signature.isSignatureValid());
			assertTrue(Utils.isCollectionNotEmpty(signature.getTimestampList()));
		}
	}

	/**
	 * These signatures are invalid because of non ordered signed attributes
	 */
	@Test
	public void manualTest() throws Exception {

		PDDocument document = PDDocument.load(getClass().getResourceAsStream(FILE_PATH));
		try (InputStream is = getClass().getResourceAsStream(FILE_PATH)) {
			byte[] pdfBytes = Utils.toByteArray(is);

			List<PDSignature> signatures = document.getSignatureDictionaries();
			assertEquals(6, signatures.size());

			int idx = 0;
			for (PDSignature pdSignature : signatures) {
				byte[] contents = pdSignature.getContents(pdfBytes);
				byte[] signedContent = pdSignature.getSignedContent(pdfBytes);

				logger.info("Byte range : " + Arrays.toString(pdSignature.getByteRange()));

				Utils.write(contents, new FileOutputStream("target/sig" + (idx++) + ".p7s"));

				ASN1InputStream asn1sInput = new ASN1InputStream(contents);
				ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();

				logger.info("SEQ : " + asn1Seq.toString());

				ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(asn1Seq.getObjectAt(0));
				assertEquals(PKCSObjectIdentifiers.signedData, oid);

				SignedData signedData = SignedData.getInstance(DERTaggedObject.getInstance(asn1Seq.getObjectAt(1)).getObject());

				ASN1Set digestAlgorithmSet = signedData.getDigestAlgorithms();
				ASN1ObjectIdentifier oidDigestAlgo = ASN1ObjectIdentifier
						.getInstance(ASN1Sequence.getInstance(digestAlgorithmSet.getObjectAt(0)).getObjectAt(0));
				DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(oidDigestAlgo.getId());
				logger.info("DIGEST ALGO : " + digestAlgorithm);

				ContentInfo encapContentInfo = signedData.getEncapContentInfo();
				ASN1ObjectIdentifier contentTypeOID = encapContentInfo.getContentType();
				logger.info("ENCAPSULATED CONTENT INFO TYPE : " + contentTypeOID);

				if (!PKCSObjectIdentifiers.id_ct_TSTInfo.equals(contentTypeOID)) { // If not timestamp
					assertEquals(PKCSObjectIdentifiers.data, contentTypeOID);

					ASN1Encodable content = encapContentInfo.getContent();
					logger.info("ENCAPSULATED CONTENT INFO CONTENT : " + content);
					assertNull(content);

					List<X509Certificate> certificates = extractCertificates(signedData);

					ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
					logger.info("SIGNER INFO ASN1 : " + signerInfosAsn1.toString());
					SignerInfo signedInfo = SignerInfo.getInstance(ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0)));

					ASN1Set authenticatedAttributeSet = signedInfo.getAuthenticatedAttributes();
					logger.info("AUTHENTICATED ATTR : " + authenticatedAttributeSet);

					Attribute attributeDigest = null;
					for (int i = 0; i < authenticatedAttributeSet.size(); i++) {
						Attribute attribute = Attribute.getInstance(authenticatedAttributeSet.getObjectAt(i));
						if (PKCSObjectIdentifiers.pkcs_9_at_messageDigest.equals(attribute.getAttrType())) {
							attributeDigest = attribute;
							break;
						}
					}

					assertNotNull(attributeDigest);

					ASN1OctetString asn1ObjString = ASN1OctetString.getInstance(attributeDigest.getAttrValues().getObjectAt(0));
					String embeddedDigest = Utils.toBase64(asn1ObjString.getOctets());
					logger.info("MESSAGE DIGEST : " + embeddedDigest);

					byte[] digestSignedContent = DSSUtils.digest(digestAlgorithm, signedContent);
					String computedDigestSignedContentEncodeBase64 = Utils.toBase64(digestSignedContent);
					logger.info("COMPUTED DIGEST SIGNED CONTENT BASE64 : " + computedDigestSignedContentEncodeBase64);
					assertEquals(embeddedDigest, computedDigestSignedContentEncodeBase64);

					SignerIdentifier sid = signedInfo.getSID();
					logger.info("SIGNER IDENTIFIER : " + sid.getId());

					IssuerAndSerialNumber issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(signedInfo.getSID());
					ASN1Integer signerSerialNumber = issuerAndSerialNumber.getSerialNumber();
					logger.info("ISSUER AND SN : " + issuerAndSerialNumber.getName() + " " + signerSerialNumber);

					BigInteger serial = issuerAndSerialNumber.getSerialNumber().getValue();
					X509Certificate signerCertificate = null;
					for (X509Certificate x509Certificate : certificates) {
						if (serial.equals(x509Certificate.getSerialNumber())) {
							signerCertificate = x509Certificate;
						}
					}
					assertNotNull(signerCertificate);

					String algorithm = signerCertificate.getPublicKey().getAlgorithm();
					EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forName(algorithm);

					ASN1OctetString encryptedInfoOctedString = signedInfo.getEncryptedDigest();
					String signatureValue = Hex.toHexString(encryptedInfoOctedString.getOctets());

					logger.info("SIGNATURE VALUE : " + signatureValue);

					Cipher cipher = Cipher.getInstance(encryptionAlgorithm.getName());
					cipher.init(Cipher.DECRYPT_MODE, signerCertificate);
					byte[] decrypted = cipher.doFinal(encryptedInfoOctedString.getOctets());

					ASN1InputStream inputDecrypted = new ASN1InputStream(decrypted);

					ASN1Sequence seqDecrypt = (ASN1Sequence) inputDecrypted.readObject();
					logger.info("DECRYPTED : " + seqDecrypt);

					DigestInfo digestInfo = new DigestInfo(seqDecrypt);
					assertEquals(oidDigestAlgo, digestInfo.getAlgorithmId().getAlgorithm());

					String decryptedDigestEncodeBase64 = Utils.toBase64(digestInfo.getDigest());
					logger.info("DECRYPTED BASE64 : " + decryptedDigestEncodeBase64);

					byte[] encoded = authenticatedAttributeSet.getEncoded();
					byte[] digest = DSSUtils.digest(digestAlgorithm, encoded);
					String computedDigestFromSignatureEncodeBase64 = Utils.toBase64(digest);
					logger.info("COMPUTED DIGEST FROM SIGNATURE BASE64 : " + computedDigestFromSignatureEncodeBase64);

					assertEquals(decryptedDigestEncodeBase64, computedDigestFromSignatureEncodeBase64);

					Utils.closeQuietly(inputDecrypted);

				}

				Utils.closeQuietly(asn1sInput);
			}
		}
		document.close();
	}

	private List<X509Certificate> extractCertificates(SignedData signedData) throws Exception {
		ASN1Set certificates = signedData.getCertificates();
		logger.info("CERTIFICATES (" + certificates.size() + ") : " + certificates);

		List<X509Certificate> foundCertificates = new ArrayList<X509Certificate>();
		for (int i = 0; i < certificates.size(); i++) {
			ASN1Sequence seqCertif = ASN1Sequence.getInstance(certificates.getObjectAt(i));

			X509CertificateHolder certificateHolder = new X509CertificateHolder(seqCertif.getEncoded());
			CertificateToken certificate = DSSASN1Utils.getCertificate(certificateHolder);

			foundCertificates.add(certificate.getCertificate());
		}
		return foundCertificates;
	}

}
