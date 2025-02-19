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
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.OID;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CAdESLevelTWithSignaturePolicyStoreTest extends AbstractCAdESTestSignature {

	private static final String HTTP_SPURI_TEST = "http://spuri.test";
	private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";

	private static final DSSDocument POLICY_CONTENT = new InMemoryDocument(CAdESLevelTWithSignaturePolicyStoreTest.class.getResourceAsStream("/validation/signature-policy.der"));

	private CAdESService service;
	private CAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello world".getBytes());

		Policy signaturePolicy = new Policy();
		signaturePolicy.setId(SIGNATURE_POLICY_ID);

		signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA256);
		signaturePolicy.setDigestValue(Utils.fromBase64("UB1ptLcfxuVzI8LHQTGpyMYkCb43i6eI3CiFVWEbnlg="));
		signaturePolicy.setSpuri(HTTP_SPURI_TEST);

		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);

		service = new CAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getGoodTsa());
	}
	
	@Override
	protected DSSDocument sign() {
		DSSDocument signedDocument = super.sign();

		SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
		signaturePolicyStore.setSignaturePolicyContent(POLICY_CONTENT);
		SpDocSpecification spDocSpec = new SpDocSpecification();
		spDocSpec.setId(SIGNATURE_POLICY_ID);
		signaturePolicyStore.setSpDocSpecification(spDocSpec);
		DSSDocument signedDocumentWithSignaturePolicyStore = service.addSignaturePolicyStore(signedDocument, signaturePolicyStore);
		assertNotNull(signedDocumentWithSignaturePolicyStore);
		
		return signedDocumentWithSignaturePolicyStore;
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		
		try {
			ASN1InputStream asn1sInput = new ASN1InputStream(byteArray);
			ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();
			
			assertEquals(2, asn1Seq.size());
			ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(asn1Seq.getObjectAt(0));
			assertEquals(PKCSObjectIdentifiers.signedData, oid);

			ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(asn1Seq.getObjectAt(1));
			SignedData signedData = SignedData.getInstance(taggedObj.getBaseObject());

			ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
			assertEquals(1, signerInfosAsn1.size());

			SignerInfo signerInfo = SignerInfo.getInstance(ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0)));

			ASN1Set unauthenticatedAttributes = signerInfo.getUnauthenticatedAttributes();
			boolean signaturePolicyStoreFound = false;
			if (unauthenticatedAttributes != null) {
				for (int i = 0; i < unauthenticatedAttributes.size(); i++) {
					ASN1Sequence attrSeq = ASN1Sequence.getInstance(unauthenticatedAttributes.getObjectAt(i));
					ASN1ObjectIdentifier attrOid = ASN1ObjectIdentifier.getInstance(attrSeq.getObjectAt(0));
					if (OID.id_aa_ets_sigPolicyStore.equals(attrOid)) {
						signaturePolicyStoreFound = true;
						
						DLSet dlSet = (DLSet) attrSeq.getObjectAt(1);
						assertEquals(1, dlSet.size());
						
						ASN1Sequence sequence = (ASN1Sequence) dlSet.getObjectAt(0);
						assertEquals(2, sequence.size());
						
						assertEquals(SIGNATURE_POLICY_ID, ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0)).toString());
						assertArrayEquals(DSSUtils.toByteArray(POLICY_CONTENT), DEROctetString.getInstance(sequence.getObjectAt(1)).getOctets());
					}
				}
			}
			assertTrue(signaturePolicyStoreFound);

			Utils.closeQuietly(asn1sInput);
		} catch (Exception e) {
			fail(e);
		}
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		assertEquals(1, signatures.size());
		
		CAdESSignature cadesSignature = (CAdESSignature) signatures.get(0);
		SignaturePolicyStore extractedSPS = cadesSignature.getSignaturePolicyStore();
		assertNotNull(extractedSPS);
		assertNotNull(extractedSPS.getSpDocSpecification());
		assertEquals(SIGNATURE_POLICY_ID, extractedSPS.getSpDocSpecification().getId());
		assertArrayEquals(DSSUtils.toByteArray(POLICY_CONTENT), DSSUtils.toByteArray(extractedSPS.getSignaturePolicyContent()));
	}
	
	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isPolicyPresent());
		
		assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
		assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
		
		assertTrue(signature.isPolicyAsn1Processable());
		assertTrue(signature.isPolicyIdentified());
		assertTrue(signature.isPolicyDigestValid());
		assertTrue(signature.isPolicyDigestAlgorithmsEqual());
	}
	
	@Override
	protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyStore(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyStoreId());
		
		XmlDigestAlgoAndValue policyStoreDigestAlgoAndValue = signature.getPolicyStoreDigestAlgoAndValue();
		assertNotNull(policyStoreDigestAlgoAndValue);
		assertNotNull(policyStoreDigestAlgoAndValue.getDigestMethod());
		assertTrue(Utils.isArrayNotEmpty(policyStoreDigestAlgoAndValue.getDigestValue()));
		
		XmlDigestAlgoAndValue policyDigestAlgoAndValue = signature.getPolicyDigestAlgoAndValue();
		assertEquals(policyDigestAlgoAndValue.getDigestMethod(), policyStoreDigestAlgoAndValue.getDigestMethod());
		assertArrayEquals(policyDigestAlgoAndValue.getDigestValue(), policyStoreDigestAlgoAndValue.getDigestValue());
		
		// ASN.1 processing
		assertFalse(Arrays.equals(POLICY_CONTENT.getDigestValue(policyDigestAlgoAndValue.getDigestMethod()), policyDigestAlgoAndValue.getDigestValue()));
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
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
