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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.CMSDocumentAnalyzer;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CAdESLevelBTest extends AbstractCAdESTestSignature {

	private static final String HELLO_WORLD = "Hello World";

	private static final Logger logger = LoggerFactory.getLogger(CAdESLevelBTest.class);

	private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes());

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());

		SignerLocation signerLocation = new SignerLocation();
		signerLocation.setCountry("LU");
		signerLocation.setLocality("Kehlen");
		signerLocation.setPostalAddress(Arrays.asList("Line1", "Line2"));
		signatureParameters.bLevel().setSignerLocation(signerLocation);

		signatureParameters.bLevel().setClaimedSignerRoles(Arrays.asList("supplier"));
		signatureParameters.bLevel().setCommitmentTypeIndications(Arrays.asList(CommitmentTypeEnum.ProofOfApproval, CommitmentTypeEnum.ProofOfCreation));

		signatureParameters.setContentHintsType("1.2.840.113549.1.7.1");
		signatureParameters.setContentHintsDescription("text/plain");
		signatureParameters.setContentIdentifierPrefix("TEST-PREFIX");
		// signatureParameters.setContentIdentifierSuffix("TEST-SUFFIX");

		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

		service = new CAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
		super.verifyDiagnosticData(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(Utils.isStringNotBlank(signature.getContentHints()));
		assertTrue(Utils.isStringNotBlank(signature.getContentIdentifier()));
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);

		try {
			CMSDocumentAnalyzer cmsDocumentAnalyzer = new CMSDocumentAnalyzer(new InMemoryDocument(byteArray));
			List<AdvancedSignature> signatures = cmsDocumentAnalyzer.getSignatures();
			assertEquals(1, signatures.size());
            assertInstanceOf(CAdESSignature.class, signatures.get(0));
			
			CAdESSignature signature = (CAdESSignature) signatures.get(0);
			assertNotNull(signature.getCMS());
			assertTrue(Utils.isArrayNotEmpty(signature.getMessageDigestValue()));

			ASN1InputStream asn1sInput = new ASN1InputStream(byteArray);
			ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();

			logger.info(String.format("SEQ : %s", asn1Seq.toString()));

			assertEquals(2, asn1Seq.size());

			ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(asn1Seq.getObjectAt(0));
			assertEquals(PKCSObjectIdentifiers.signedData, oid);
			logger.info(String.format("OID : %s", oid.toString()));

			ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(asn1Seq.getObjectAt(1));

			logger.info(String.format("TAGGED OBJ : %s", taggedObj.toString()));

			ASN1Object object = taggedObj.getBaseObject();
			logger.info(String.format("OBJ : %s", object.toString()));

			SignedData signedData = SignedData.getInstance(object);
			logger.info(String.format("SIGNED DATA : %s", signedData));

			ASN1Set digestAlgorithms = signedData.getDigestAlgorithms();
			logger.info(String.format("DIGEST ALGOS : %s", digestAlgorithms.toString()));

			ContentInfo encapContentInfo = signedData.getEncapContentInfo();
			logger.info(String.format("ENCAPSULATED CONTENT INFO : %s %s", encapContentInfo.getContentType(), encapContentInfo.getContent()));

			ASN1Set certificates = signedData.getCertificates();
			logger.info(String.format("CERTIFICATES (%s) : %s", certificates.size(), certificates));

			List<X509Certificate> foundCertificates = new ArrayList<>();
			for (int i = 0; i < certificates.size(); i++) {
				ASN1Sequence seqCertif = ASN1Sequence.getInstance(certificates.getObjectAt(i));
				logger.info(String.format("SEQ cert %s : %s", i, seqCertif));

				X509CertificateHolder certificateHolder = new X509CertificateHolder(seqCertif.getEncoded());
				CertificateToken certificate = DSSASN1Utils.getCertificate(certificateHolder);
				X509Certificate x509Certificate = certificate.getCertificate();
				x509Certificate.checkValidity();

				logger.info(String.format("Cert %s : %s", i, certificate));

				foundCertificates.add(x509Certificate);
			}

			ASN1Set crLs = signedData.getCRLs();
			logger.info(String.format("CRLs : %s", crLs));

			ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
			logger.info(String.format("SIGNER INFO ASN1 : %s", signerInfosAsn1.toString()));
			assertEquals(1, signerInfosAsn1.size());

			ASN1Sequence seqSignedInfo = ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0));

			SignerInfo signedInfo = SignerInfo.getInstance(seqSignedInfo);
			logger.info(String.format("SIGNER INFO : %s", signedInfo.toString()));

			SignerIdentifier sid = signedInfo.getSID();
			logger.info(String.format("SIGNER IDENTIFIER : %s", sid.getId()));

			IssuerAndSerialNumber issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(signedInfo.getSID());
			logger.info(String.format("ISSUER AND SN : %s", issuerAndSerialNumber.toString()));

			BigInteger serial = issuerAndSerialNumber.getSerialNumber().getValue();

			X509Certificate signerCertificate = null;
			for (X509Certificate x509Certificate : foundCertificates) {
				// TODO check issuer name
				if (serial.equals(x509Certificate.getSerialNumber())) {
					signerCertificate = x509Certificate;
				}
			}
			assertNotNull(signerCertificate);

			ASN1OctetString encryptedDigest = signedInfo.getEncryptedDigest();
			logger.info(String.format("ENCRYPT DIGEST : %s", encryptedDigest.toString()));

			ASN1Sequence seq = ASN1Sequence.getInstance(object);

			ASN1Integer version = ASN1Integer.getInstance(seq.getObjectAt(0));
			logger.info(String.format("VERSION : %s", version.toString()));

			ASN1Set digestManualSet = ASN1Set.getInstance(seq.getObjectAt(1));
			logger.info(String.format("DIGEST SET : %s", digestManualSet.toString()));
			assertEquals(digestAlgorithms, digestManualSet);

			ASN1Sequence seqDigest = ASN1Sequence.getInstance(digestManualSet.getObjectAt(0));
			// assertEquals(1, seqDigest.size());

			ASN1ObjectIdentifier oidDigestAlgo = ASN1ObjectIdentifier.getInstance(seqDigest.getObjectAt(0));
			assertEquals(new ASN1ObjectIdentifier(DigestAlgorithm.SHA512.getOid()), oidDigestAlgo);

			ASN1Sequence seqEncapsulatedInfo = ASN1Sequence.getInstance(seq.getObjectAt(2));
			logger.info(String.format("ENCAPSULATED INFO : %s", seqEncapsulatedInfo.toString()));

			ASN1ObjectIdentifier oidContentType = ASN1ObjectIdentifier.getInstance(seqEncapsulatedInfo.getObjectAt(0));
			logger.info(String.format("OID CONTENT TYPE : %s", oidContentType.toString()));

			ASN1TaggedObject taggedContent = ASN1TaggedObject.getInstance(seqEncapsulatedInfo.getObjectAt(1));

			ASN1OctetString contentOctetString = ASN1OctetString.getInstance(taggedContent.getBaseObject());
			String content = new String(contentOctetString.getOctets());
			assertEquals(HELLO_WORLD, content);
			logger.info(String.format("CONTENT : %s", content));

			byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA512, HELLO_WORLD.getBytes());
			String encodeHexDigest = Hex.toHexString(digest);
			logger.info(String.format("CONTENT DIGEST COMPUTED : %s", encodeHexDigest));

			ASN1Set authenticatedAttributes = signedInfo.getAuthenticatedAttributes();
			logger.info(String.format("AUTHENTICATED ATTRIBUTES : %s", authenticatedAttributes.toString()));

			// ASN1Sequence seqAuthAttrib = ASN1Sequence.getInstance(authenticatedAttributes.getObjectAt(0));

			logger.info(String.format("Nb Auth Attributes : %s", authenticatedAttributes.size()));

			String embeddedDigest = "";
			for (int i = 0; i < authenticatedAttributes.size(); i++) {
				ASN1Sequence authAttrSeq = ASN1Sequence.getInstance(authenticatedAttributes.getObjectAt(i));
				logger.info(authAttrSeq.toString());
				ASN1ObjectIdentifier attrOid = ASN1ObjectIdentifier.getInstance(authAttrSeq.getObjectAt(0));
				if (PKCSObjectIdentifiers.pkcs_9_at_messageDigest.equals(attrOid)) {
					ASN1Set setMessageDigest = ASN1Set.getInstance(authAttrSeq.getObjectAt(1));
					ASN1OctetString asn1ObjString = ASN1OctetString.getInstance(setMessageDigest.getObjectAt(0));
					embeddedDigest = Hex.toHexString(asn1ObjString.getOctets());
				}
			}
			assertEquals(encodeHexDigest, embeddedDigest);

			ASN1OctetString encryptedInfoOctetString = signedInfo.getEncryptedDigest();
			String signatureValue = Hex.toHexString(encryptedInfoOctetString.getOctets());

			logger.info(String.format("SIGNATURE VALUE : %s", signatureValue));

			Cipher cipher = Cipher.getInstance("RSA", "SunJCE");
			cipher.init(Cipher.DECRYPT_MODE, signerCertificate);
			byte[] decrypted = cipher.doFinal(encryptedInfoOctetString.getOctets());

			ASN1InputStream inputDecrypted = new ASN1InputStream(decrypted);

			ASN1Sequence seqDecrypt = (ASN1Sequence) inputDecrypted.readObject();
			logger.info(String.format("Decrypted : %s", seqDecrypt));

			DigestInfo digestInfo = new DigestInfo(seqDecrypt);
			assertEquals(oidDigestAlgo, digestInfo.getAlgorithmId().getAlgorithm());

			String decryptedDigestEncodeBase64 = Utils.toBase64(digestInfo.getDigest());
			logger.info(String.format("Decrypted Base64 : %s", decryptedDigestEncodeBase64));

			byte[] encoded = signedInfo.getAuthenticatedAttributes().getEncoded();
			MessageDigest messageDigest = MessageDigest.getInstance(DigestAlgorithm.SHA512.getName());
			byte[] digestOfAuthenticatedAttributes = messageDigest.digest(encoded);

			String computedDigestEncodeBase64 = Utils.toBase64(digestOfAuthenticatedAttributes);
			logger.info(String.format("Computed Base64 : %s", computedDigestEncodeBase64));

			assertEquals(decryptedDigestEncodeBase64, computedDigestEncodeBase64);

			Utils.closeQuietly(asn1sInput);
			Utils.closeQuietly(inputDecrypted);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	@Override
	protected void checkMimeType(DiagnosticData diagnosticData) {
		super.checkMimeType(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNull(signature.getMimeType()); // ContentHints defined
	}
	
	@Override
	protected void checkDTBSR(DiagnosticData diagnosticData) {
		super.checkDTBSR(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		XmlDigestAlgoAndValue dtbsr = signature.getDataToBeSignedRepresentation();
		
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, getSignatureParameters());
		assertArrayEquals(DSSUtils.digest(dtbsr.getDigestMethod(), dataToSign.getBytes()), dtbsr.getDigestValue());
	}
	
	@Override
	protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
		super.verifyOriginalDocuments(validator, diagnosticData);
		
		List<DSSDocument> results = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
		assertEquals(1, results.size());

		String firstDocument = new String(DSSUtils.toByteArray(documentToSign));
		String secondDocument = new String(DSSUtils.toByteArray(results.get(0)));
		assertEquals(firstDocument, secondDocument);

		byte[] digest = documentToSign.getDigestValue(DigestAlgorithm.SHA256);
		byte[] digest2 = results.get(0).getDigestValue(DigestAlgorithm.SHA256);
		assertArrayEquals(digest, digest2);
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeTypeEnum.PKCS7;
	}

	@Override
	protected boolean isBaselineT() {
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		return false;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
