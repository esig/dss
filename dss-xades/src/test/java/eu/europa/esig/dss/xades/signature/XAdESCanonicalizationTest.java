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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.dss.xml.common.definition.AbstractPath;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag("slow")
class XAdESCanonicalizationTest extends AbstractXAdESTestSignature {
	
	private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	private String canonicalizationKeyInfo;
	private String canonicalizationSignedProperties;
	private String canonicalizationSignedInfo;
	private SignaturePackaging packaging;

	private static Stream<Arguments> data() {
		Object[] arr = { Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS };
		return random(arr);
	}

	static Stream<Arguments> random(Object[] arr) {
		List<Arguments> args = new ArrayList<>();
		for (int i = 0; i < arr.length; i++) {
			for (int h = 0; h < arr.length; h++) {
				for (int j = 0; j < arr.length; j++) {
					args.add(Arguments.of(arr[i], arr[h], arr[j], SignaturePackaging.ENVELOPED));
					args.add(Arguments.of(arr[i], arr[h], arr[j], SignaturePackaging.ENVELOPING));
				}
			}
		}
		return args.stream();
	}

	@ParameterizedTest(name = "Canonicalization {index} : {0} - {1} - {2} - {3}")
	@MethodSource("data")
	void init(String canonicalizationKeyInfo, String canonicalizationSignedProperties, String canonicalizationSignedInfo, SignaturePackaging packaging) {
		this.canonicalizationKeyInfo = canonicalizationKeyInfo;
		this.canonicalizationSignedProperties = canonicalizationSignedProperties;
		this.canonicalizationSignedInfo = canonicalizationSignedInfo;
		this.packaging = packaging;

		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(packaging);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		signatureParameters.setSignKeyInfo(true);
		signatureParameters.setKeyInfoCanonicalizationMethod(canonicalizationKeyInfo);
		signatureParameters.setSignedPropertiesCanonicalizationMethod(canonicalizationSignedProperties);
		signatureParameters.setSignedInfoCanonicalizationMethod(canonicalizationSignedInfo);

		service = new XAdESService(getOfflineCertificateVerifier());

		super.signAndVerify();
	}

	@Override
	public void signAndVerify() {
		// skip global test
	}

	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		saveDocumentAndDelete(byteArray);

		try {
			Document doc = DomUtils.buildDOM(byteArray);

			checkKeyInfo(doc);
			checkSignedProperties(doc);
			checkOriginalDocument(doc);

			// ------------------------------------ SIGNED INFO
			// -----------------------------------------------------
			// Signed info extraction
			NodeList signedInfoNodeList = DomUtils.getNodeList(doc, AbstractPath.all(XMLDSigElement.SIGNED_INFO));
			assertNotNull(signedInfoNodeList);
			assertEquals(1, signedInfoNodeList.getLength());

			Node signedInfo = signedInfoNodeList.item(0);

			// ------------------------------------ SIGNATURE VERIFICATION
			// -----------------------------------------------------
			String signatureValueBase64 = DomUtils.getValue(doc, "//ds:Signature/ds:SignatureValue");
			assertNotNull(signatureValueBase64);

			byte[] canonicalized = XMLCanonicalizer.createInstance(canonicalizationSignedInfo).canonicalize(signedInfo);

			byte[] sigValue = Utils.fromBase64(signatureValueBase64);

			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(getSigningCert().getPublicKey());
			signature.update(canonicalized);
			boolean verify = signature.verify(sigValue);
			assertTrue(verify);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	private void checkOriginalDocument(Document doc) throws Exception {
		// ------------------------------------ ORIGINAL FILE
		// -----------------------------------------------------
		String originalFileDigest;
		byte[] originalFileByteArray;
		if (packaging == SignaturePackaging.ENVELOPED) {
			// Original File base64 extraction + Verification
			originalFileDigest = getReferenceDigest(doc, "");

			NodeList transformNodes = getReferenceTransforms(doc, "");
			String algo = getTransformAlgo(transformNodes.item(1));

			File orginalFile = new File("src/test/resources/sample.xml");
			// Transform original file into byte array
			byte[] fileContent = Files.readAllBytes(orginalFile.toPath());
			originalFileByteArray = XMLCanonicalizer.createInstance(algo).canonicalize(fileContent);
		} else {
			// Original File base64 extraction + Verification
			NodeList originalFileNodeList = DomUtils.getNodeList(doc, AbstractPath.all(XMLDSigElement.OBJECT));
			assertNotNull(originalFileNodeList);
			assertEquals(2, originalFileNodeList.getLength());

			Node orignalFile = originalFileNodeList.item(1);

			NamedNodeMap originalFileAttributes = orignalFile.getAttributes();
			Node originalFileId = originalFileAttributes.getNamedItem("Id");
			assertNotNull(originalFileId);

			// Extract original file digest
			originalFileDigest = getReferenceDigest(doc, "#" + originalFileId.getNodeValue());

			// Calculate Original File digest from retrieved base64
			String originalBase64String = orignalFile.getTextContent();
			// Get byte array from base64 string
			originalFileByteArray = Base64.getDecoder().decode(originalBase64String);
		}

		// Calculate Original File Digest
		byte[] digestOriginalFile = DSSUtils.digest(DigestAlgorithm.SHA256, originalFileByteArray);
		String originalDigestBase64 = Base64.getEncoder().encodeToString(digestOriginalFile);

		// Assert that both values are equivalent
		assertEquals(originalFileDigest, originalDigestBase64);
	}

	private void checkKeyInfo(Document doc) {
		// ------------------------------------ KEY INFO
		// -----------------------------------------------------
		// Key info extraction + Verification
		NodeList keyInfoNodeList = DomUtils.getNodeList(doc, AbstractPath.all(XMLDSigElement.KEY_INFO));
		assertNotNull(keyInfoNodeList);
		assertEquals(1, keyInfoNodeList.getLength());

		Node keyInfo = keyInfoNodeList.item(0);

		NamedNodeMap keyInfoAttributes = keyInfo.getAttributes();
		Node keyInfoId = keyInfoAttributes.getNamedItem("Id");
		assertNotNull(keyInfoId);

		// Verify KeyInfo Canonicalization Algorithm
		NodeList transformNodes = getReferenceTransforms(doc, "#" + keyInfoId.getNodeValue());
		String keyInfoTransformAlgo = getTransformAlgo(transformNodes.item(0));
		assertEquals(canonicalizationKeyInfo, keyInfoTransformAlgo);

		// Verify KeyInfo Digest
		String keyInfoDigest = getReferenceDigest(doc, "#" + keyInfoId.getNodeValue());
		byte[] canonicalizedKeyInfo = XMLCanonicalizer.createInstance(canonicalizationKeyInfo).canonicalize(keyInfo);
		byte[] digestKeyInfo = DSSUtils.digest(DigestAlgorithm.SHA256, canonicalizedKeyInfo);
		String keyInfoBase64 = Base64.getEncoder().encodeToString(digestKeyInfo);
		assertEquals(keyInfoBase64, keyInfoDigest);
	}

	private void checkSignedProperties(Document doc) {
		// ------------------------------------ SIGNED PROPERTIES
		// -----------------------------------------------------
		try {
			// Signed properties extraction + verification
			NodeList signedPropertiesNodeList = DomUtils.getNodeList(doc, AbstractPath.all(XAdES132Element.SIGNED_PROPERTIES));
			assertNotNull(signedPropertiesNodeList);
			assertEquals(1, signedPropertiesNodeList.getLength());

			Node signedProperties = signedPropertiesNodeList.item(0);

			NamedNodeMap signedPropertiesAttributes = signedProperties.getAttributes();
			Node signedPropertiesId = signedPropertiesAttributes.getNamedItem("Id");
			assertNotNull(signedPropertiesId);

			// Verify KeyInfo Canonicalization Algorithm
			NodeList transformNodes = getReferenceTransforms(doc, "#" + signedPropertiesId.getNodeValue());
			String signedPropertiesTransformAlgo = getTransformAlgo(transformNodes.item(0));
			assertEquals(canonicalizationSignedProperties, signedPropertiesTransformAlgo);

			// Verify KeyInfo Digest
			String signedPropertiesDigest = getReferenceDigest(doc, "#" + signedPropertiesId.getNodeValue());
			byte[] canonicalizedSignedProperties = XMLCanonicalizer.createInstance(canonicalizationSignedProperties).canonicalize(signedProperties);
			byte[] digestProperties = DSSUtils.digest(DigestAlgorithm.SHA256, canonicalizedSignedProperties);
			String propertiesBase64 = Base64.getEncoder().encodeToString(digestProperties);
			assertEquals(propertiesBase64, signedPropertiesDigest);
		} catch (Exception e) {
			fail(e.getMessage());
		}
	}

	private void saveDocumentAndDelete(byte[] byteArray) {
		File file = new File("target/sample-sig.xml");
		// Create File and Output Stream
		try (FileOutputStream fos = new FileOutputStream(file)) {
			// Write signature to file
			Utils.write(byteArray, fos);
		} catch (Exception e) {
			fail(e.getMessage());
		}
		assertTrue(file.exists());
		assertTrue(file.delete(), "Cannot delete the document (IO error)");
		assertFalse(file.exists());
	}

	private NodeList getReferenceTransforms(Document doc, String uri) {
		NodeList referenceTransform = DomUtils.getNodeList(doc, "//ds:Reference[@URI = '" + uri + "']/ds:Transforms/ds:Transform");
		assertNotNull(referenceTransform);
		return referenceTransform;
	}

	private String getTransformAlgo(Node node) {
		NamedNodeMap attributes = node.getAttributes();
		Node transform = attributes.getNamedItem("Algorithm");
		assertNotNull(transform);
		return transform.getNodeValue();
	}

	private String getReferenceDigest(Document doc, String uri) {
		Node referenceDigest = DomUtils.getNode(doc, "//ds:Reference[@URI = '" + uri + "']/ds:DigestValue");
		assertNotNull(referenceDigest);
		return referenceDigest.getTextContent();
	}

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
		return service;
	}

	@Override
	protected XAdESSignatureParameters getSignatureParameters() {
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
