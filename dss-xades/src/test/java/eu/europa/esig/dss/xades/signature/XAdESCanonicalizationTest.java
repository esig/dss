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

package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

@RunWith(Parameterized.class)
public class XAdESCanonicalizationTest extends AbstractXAdESTestSignature {
	private DocumentSignatureService<XAdESSignatureParameters> service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	private String canonicalizationKeyInfo;
	private String canonicalizationSignedProperties;
	private String canonicalizationSignedInfo;
	private SignaturePackaging packaging;

	
 	@Parameters(name = "Canonicalization {index} : {0} - {1} - {2} - {3}")
	public static Collection<Object[]> data() {
	    Object[] arr = {Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS };
	    return random(arr);
	}
	
	static Collection<Object[]> random(Object[] arr) {
		List<Object[]> list = new ArrayList<Object[]>();
		for(int i = 0; i<arr.length; i++) {
			for(int h = 0; h < arr.length; h++) {
				for(int j = 0; j < arr.length; j++) {
					Object[] array1 = {arr[i], arr[h], arr[j], SignaturePackaging.ENVELOPED};
					Object[] array2 = {arr[i], arr[h], arr[j], SignaturePackaging.ENVELOPING};
					list.add(array1);
					list.add(array2);
				}	
			}
		}
		return list;
	}

	public XAdESCanonicalizationTest(String canonicalizationKeyInfo, String canonicalizationSignedProperties, 
			String canonicalizationSignedInfo, SignaturePackaging packaging) {
		this.canonicalizationKeyInfo = canonicalizationKeyInfo;
		this.canonicalizationSignedProperties = canonicalizationSignedProperties;
		this.canonicalizationSignedInfo = canonicalizationSignedInfo;
		this.packaging = packaging;
	}


	@Before
	public void init() throws Exception {
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

		service = new XAdESService(getCompleteCertificateVerifier());
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

			//------------------------------------ SIGNED INFO -----------------------------------------------------
			// Signed info extraction
			NodeList signedInfoNodeList = DomUtils.getNodeList(doc, "//ds:SignedInfo");
			assertNotNull(signedInfoNodeList);
			assertEquals(1, signedInfoNodeList.getLength());
			
			Node signedInfo = signedInfoNodeList.item(0);

			//------------------------------------ SIGNATURE VERIFICATION -----------------------------------------------------
			Canonicalizer canonicalizer = Canonicalizer.getInstance(canonicalizationSignedInfo);
			String signatureValueBase64 = DomUtils.getValue(doc, "//ds:Signature/ds:SignatureValue");
			assertNotNull(signatureValueBase64);
			
			byte[] canonicalized = canonicalizer.canonicalizeSubtree(signedInfo);	

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
		//------------------------------------ ORIGINAL FILE -----------------------------------------------------
		String originalFileDigest = "";
		byte[] originalFilByteArray = null;
		
		if(packaging == SignaturePackaging.ENVELOPED) {		
			// Original File base64 extraction + Verification
			originalFileDigest = getReferenceDigest(doc, "");

			NodeList transformNodes = getReferenceTransforms(doc, "");
			String algo = getTransformAlgo(transformNodes.item(1));
			
			Canonicalizer canonicalizer = Canonicalizer.getInstance(algo);
			
			File orginalFile = new File("src/test/resources/sample.xml");
			// Transform original file into byte array
			byte[] fileContent = Files.readAllBytes(orginalFile.toPath());
			originalFilByteArray = canonicalizer.canonicalize(fileContent);
		}else {
			// Original File base64 extraction + Verification
			NodeList originalFileNodeList = DomUtils.getNodeList(doc, "//ds:Object");
			assertNotNull(originalFileNodeList);
			assertEquals(2, originalFileNodeList.getLength());
			
			Node orignalFile = originalFileNodeList.item(1);
			
			NamedNodeMap originalFileAttributes = orignalFile.getAttributes();
			Node originalFileId = originalFileAttributes.getNamedItem("Id");
			assertNotNull(originalFileId);		
			
			// Extract original file digest
			originalFileDigest = getReferenceDigest(doc, "#"+originalFileId.getNodeValue());
			
			// Calculate Original File digest from retrieved base64
			String originalBase64String = orignalFile.getTextContent();
			// Get byte array from base64 string
			originalFilByteArray = Base64.getDecoder().decode(originalBase64String);
		}
		
		// Calculate Original File Digest
		byte[] digestOriginalFile = DSSUtils.digest(DigestAlgorithm.SHA256, originalFilByteArray);
		String originalDigestBase64 = Base64.getEncoder().encodeToString(digestOriginalFile);
		
		// Assert that both values are equivalent
		assertEquals(originalFileDigest, originalDigestBase64);
	}



	private void checkKeyInfo(Document doc) throws InvalidCanonicalizerException, CanonicalizationException {
		//------------------------------------ KEY INFO -----------------------------------------------------
		// Key info extraction + Verification
		NodeList keyInfoNodeList = DomUtils.getNodeList(doc, "//ds:KeyInfo");
		assertNotNull(keyInfoNodeList);
		assertEquals(1, keyInfoNodeList.getLength());
		
		Node keyInfo = keyInfoNodeList.item(0);
		
		NamedNodeMap keyInfoAttributes = keyInfo.getAttributes();
		Node keyInfoId = keyInfoAttributes.getNamedItem("Id");
		assertNotNull(keyInfoId);
		
		Canonicalizer canonicalizer = Canonicalizer.getInstance(canonicalizationKeyInfo);
		
		// Verify KeyInfo Canonicalization Algorithm
		NodeList transformNodes = getReferenceTransforms(doc, "#"+keyInfoId.getNodeValue());
		String keyInfoTransformAlgo = getTransformAlgo(transformNodes.item(0));
		assertEquals(canonicalizer.getURI(), keyInfoTransformAlgo);
		
		// Verify KeyInfo Digest
		String keyInfoDigest = getReferenceDigest(doc, "#"+keyInfoId.getNodeValue());
		byte[] canonicalizedKeyInfo = canonicalizer.canonicalizeSubtree(keyInfo);						
		byte[] digestKeyInfo = DSSUtils.digest(DigestAlgorithm.SHA256, canonicalizedKeyInfo);
		String keyInfoBase64 = Base64.getEncoder().encodeToString(digestKeyInfo);
		assertEquals(keyInfoBase64, keyInfoDigest);
	}
	
	
	private void checkSignedProperties(Document doc) {
		//------------------------------------ SIGNED PROPERTIES -----------------------------------------------------
		try {
			// Signed properties extraction + verification
			NodeList signedPropertiesNodeList = DomUtils.getNodeList(doc, "//xades:SignedProperties");
			assertNotNull(signedPropertiesNodeList);
			assertEquals(1, signedPropertiesNodeList.getLength());
			
			Node signedProperties = signedPropertiesNodeList.item(0);
			
			NamedNodeMap signedPropertiesAttributes = signedProperties.getAttributes();
			Node signedPropertiesId = signedPropertiesAttributes.getNamedItem("Id");
			assertNotNull(signedPropertiesId);
			
			Canonicalizer canonicalizer = Canonicalizer.getInstance(canonicalizationSignedProperties);
			
			// Verify KeyInfo Canonicalization Algorithm
			NodeList transformNodes = getReferenceTransforms(doc, "#"+signedPropertiesId.getNodeValue());
			String signedPropertiesTransformAlgo = getTransformAlgo(transformNodes.item(0));
			assertEquals(canonicalizer.getURI(), signedPropertiesTransformAlgo);
			
			// Verify KeyInfo Digest
			String signedPropertiesDigest = getReferenceDigest(doc, "#"+signedPropertiesId.getNodeValue());
			byte[] canonicalizedSignedProperties = canonicalizer.canonicalizeSubtree(signedProperties);		
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
		assertTrue("Cannot delete the document (IO error)", file.delete());
		assertFalse(file.exists());
	}
	
	private NodeList getReferenceTransforms(Document doc, String URI) {
		NodeList referenceTransform = DomUtils.getNodeList(doc, "//ds:Reference[@URI = '" + URI + "']/ds:Transforms/ds:Transform");
		assertNotNull(referenceTransform);
		return referenceTransform;
	}

	private String getTransformAlgo(Node node) {
		NamedNodeMap attributes = node.getAttributes();
		Node transform = attributes.getNamedItem("Algorithm");
		assertNotNull(transform);
		return transform.getNodeValue();
	}
	
	private String getReferenceDigest(Document doc, String URI) {
		Node referenceDigest = DomUtils.getNode(doc, "//ds:Reference[@URI = '" + URI + "']/ds:DigestValue");	
		assertNotNull(referenceDigest);
		return referenceDigest.getTextContent();
	}	

	@Override
	protected DocumentSignatureService<XAdESSignatureParameters> getService() {
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
