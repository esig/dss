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
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.CommonObjectIdentifier;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.DSSObject;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.dataobject.DSSDataObjectFormat;
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterTransform;
import eu.europa.esig.dss.xades.reference.XPathTransform;
import eu.europa.esig.dss.xades.reference.XsltTransform;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.xades.definition.XAdESNamespace;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class SignXmlXadesBWithTransformsTest extends CookbookTools {
	
	@Test
	public void envelopedSignatureTest() throws IOException {

		// GET document to be signed -
		// Return DSSDocument toSignDocument
		prepareXmlDoc();

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::demo[]
			// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
			// import eu.europa.esig.dss.enumerations.SignatureLevel;
			// import eu.europa.esig.dss.enumerations.SignaturePackaging;
			// import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
			// import eu.europa.esig.dss.xades.reference.DSSReference;
			// import eu.europa.esig.dss.xades.reference.DSSTransform;
			// import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
			// import eu.europa.esig.dss.xades.signature.XAdESService;
			// import eu.europa.esig.dss.xades.XAdESSignatureParameters;
			// import javax.xml.crypto.dsig.CanonicalizationMethod;
			// import java.util.ArrayList;
			// import java.util.List;

			// Prepare transformations in the proper order
			List<DSSTransform> transforms = new ArrayList<>();
			// tag::demoEnvelopedTransform[]
			DSSTransform envelopedTransform = new EnvelopedSignatureTransform();
			// end::demoEnvelopedTransform[]
			transforms.add(envelopedTransform);
			// tag::demoCanonicalizationTransform[]
			DSSTransform canonicalization = new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
			// end::demoCanonicalizationTransform[]
			transforms.add(canonicalization);

			// Initialize signature parameters
			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

			// tag::demoReference[]
			List<DSSReference> references = new ArrayList<>();
			// Initialize and configure ds:Reference based on the provided signer document
			DSSReference dssReference = new DSSReference();
			dssReference.setContents(toSignDocument);
			dssReference.setId("r-" + toSignDocument.getName());
			dssReference.setTransforms(transforms);
			// set empty URI to cover the whole document
			dssReference.setUri("");
			dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
			references.add(dssReference);
			// set references
			parameters.setReferences(references);
			// end::demoReference[]

			// end::demo[]

			// tag::demoDataObjectFormat[]
			// import eu.europa.esig.dss.model.CommonObjectIdentifier;
			// import eu.europa.esig.dss.xades.dataobject.DSSDataObjectFormat;

			List<DSSDataObjectFormat> dataObjectFormatList = new ArrayList<>();
			// Initialize a custom DataObjectFormat identifying the signed data object
			DSSDataObjectFormat dataObjectFormat = new DSSDataObjectFormat();
			// Provide a reference to the signed data object
			dataObjectFormat.setObjectReference("#r-" + toSignDocument.getName());
			// Define description of the data object
			dataObjectFormat.setDescription("This describes the signed data object");
			// Define the MimeType of the data object
			dataObjectFormat.setMimeType(toSignDocument.getMimeType().getMimeTypeString());
			// Set the encoding of the data object
			dataObjectFormat.setEncoding("http://www.w3.org/2000/09/xmldsig#base64");

			// Create an object identifier for the data object
			CommonObjectIdentifier objectIdentifier = new CommonObjectIdentifier();
			// Set OID or URI of the document
			objectIdentifier.setUri("http://nowina.lu/sample");
			// Provide reference(s) to the document
			objectIdentifier.setDocumentationReferences("http://nowina.lu/docs/sample.xml");
			// Set the created ObjectIdentifier
			dataObjectFormat.setObjectIdentifier(objectIdentifier);

			// Add the created DSSDataObjectFormat to a list and set the signature parameters
			dataObjectFormatList.add(dataObjectFormat);
			parameters.setDataObjectFormatList(dataObjectFormatList);
			// end::demoDataObjectFormat[]

			DSSDocument objectContent = toSignDocument;
			// tag::demoObjects[]
			// import eu.europa.esig.dss.enumerations.MimeTypeEnum;
			// import eu.europa.esig.dss.xades.DSSObject;

			// Create a DSSObject representing a ds:Object element structure
			DSSObject object = new DSSObject();
			// Provide a content of a DSSDocument format
			object.setContent(objectContent);
			// Set the identifier
			object.setId("o-id-object");
			// Set the MimeType
			object.setMimeType(MimeTypeEnum.XML.getMimeTypeString());
			// Set the encoding
			object.setEncodingAlgorithm("http://www.w3.org/2000/09/xmldsig#base64");

			// Set the object to the signature parameters
			parameters.setObjects(Collections.singletonList(object));
			// end::demoObjects[]
			
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
			parameters.setSigningCertificate(privateKey.getCertificate());
			parameters.setCertificateChain(privateKey.getCertificateChain());

			// Configuration of several signed attributes like ...
			BLevelParameters bLevelParameters = parameters.bLevel();

			// claimed signer role(s)
			bLevelParameters.setClaimedSignerRoles(Arrays.asList("Manager"));

			// signer location
			SignerLocation signerLocation = new SignerLocation();
			signerLocation.setCountry("BE");
			signerLocation.setStateOrProvince("Luxembourg");
			signerLocation.setPostalCode("1234");
			signerLocation.setLocality("SimCity");
			bLevelParameters.setSignerLocation(signerLocation);

			// commitment type(s)
			List<CommitmentType> commitmentTypeIndications = new ArrayList<>();
			commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfOrigin);
			commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfApproval);
			bLevelParameters.setCommitmentTypeIndications(commitmentTypeIndications);

			CommonCertificateVerifier verifier = new CommonCertificateVerifier();
			XAdESService service = new XAdESService(verifier);
			service.setTspSource(getTSPSource());

			// Signature process with its 3 stateless steps
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
			
			// signedDocument.save("target/signed.xml");

			testFinalDocument(signedDocument);

			// tag::demoPrefixes[]
			// import eu.europa.esig.dss.xades.XAdESSignatureParameters;
			// import eu.europa.esig.xades.definition.XAdESNamespace;
			// import eu.europa.esig.dss.definition.DSSNamespace;
			// import javax.xml.crypto.dsig.XMLSignature;

			parameters = new XAdESSignatureParameters();
			
			// Allows setting of a XAdES namespace (changes a XAdES format)
			// Default : XAdESNamespace.XADES_132 (produces XAdES 1.3.2)
			parameters.setXadesNamespace(XAdESNamespace.XADES_132);
			
			// Defines an XmlDSig prefix
			// Default : XAdESNamespace.XMLDSIG
			parameters.setXmldsigNamespace(new DSSNamespace(XMLSignature.XMLNS, "myPrefix"));
			
			// Defines a XAdES 1.4.1 format prefix
			// Default : XAdESNamespace.XADES_141
			parameters.setXades141Namespace(XAdESNamespace.XADES_141);
			
			// end::demoPrefixes[]
		}
		
	}
	
	@Test
	public void base64TransformTest() throws IOException {

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			DSSDocument document = new InMemoryDocument("Hello World!".getBytes(), "Hello.txt", MimeTypeEnum.BINARY);
			List<DSSTransform> transforms = new ArrayList<>();
			// tag::demoBase64Transform[]
			// import eu.europa.esig.dss.xades.reference.Base64Transform;
			// import eu.europa.esig.dss.xades.reference.DSSTransform;

			DSSTransform base64Transform = new Base64Transform();
			// end::demoBase64Transform[]
			transforms.add(base64Transform);

			
			List<DSSReference> references = new ArrayList<>();
			DSSReference dssReference = new DSSReference();
			dssReference.setContents(document);
			dssReference.setId("r-" + document.getName());
			dssReference.setTransforms(transforms);
			// set empty URI to cover the whole document
			dssReference.setUri("#" + document.getName());
			dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
			references.add(dssReference);

			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
			parameters.setReferences(references);
			
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
			parameters.setSigningCertificate(privateKey.getCertificate());
			parameters.setCertificateChain(privateKey.getCertificateChain());

			BLevelParameters bLevelParameters = parameters.bLevel();

			bLevelParameters.setClaimedSignerRoles(Arrays.asList("Manager"));

			SignerLocation signerLocation = new SignerLocation();
			signerLocation.setCountry("BE");
			signerLocation.setStateOrProvince("Luxembourg");
			signerLocation.setPostalCode("1234");
			signerLocation.setLocality("SimCity");
			bLevelParameters.setSignerLocation(signerLocation);

			List<CommitmentType> commitmentTypeIndications = new ArrayList<>();
			commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfOrigin);
			commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfApproval);
			bLevelParameters.setCommitmentTypeIndications(commitmentTypeIndications);

			CommonCertificateVerifier verifier = new CommonCertificateVerifier();
			XAdESService service = new XAdESService(verifier);
			service.setTspSource(getTSPSource());

			ToBeSigned dataToSign = service.getDataToSign(document, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(document, parameters, signatureValue);
			
			// signedDocument.save("target/signed.xml");

			testFinalDocument(signedDocument);
		}
	}
	
	@Test
	public void envelopedSignatureXPathTest() throws IOException {

		prepareXmlDoc();

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			List<DSSTransform> transforms = new ArrayList<>();
			// tag::demoEnvelopedXPathTransform[]
			// import eu.europa.esig.dss.xades.reference.DSSTransform;
			// import eu.europa.esig.dss.xades.reference.XPathTransform;

			DSSTransform envelopedTransform = new XPathTransform("not(ancestor-or-self::ds:Signature)");
			// end::demoEnvelopedXPathTransform[]
			transforms.add(envelopedTransform);
			
			List<DSSReference> references = new ArrayList<>();
			DSSReference dssReference = new DSSReference();
			dssReference.setContents(toSignDocument);
			dssReference.setId("r-" + toSignDocument.getName());
			dssReference.setTransforms(transforms);
			dssReference.setUri("");
			dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
			references.add(dssReference);

			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
			parameters.setReferences(references);
			
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
			parameters.setSigningCertificate(privateKey.getCertificate());
			parameters.setCertificateChain(privateKey.getCertificateChain());

			BLevelParameters bLevelParameters = parameters.bLevel();

			bLevelParameters.setClaimedSignerRoles(Arrays.asList("Manager"));

			SignerLocation signerLocation = new SignerLocation();
			signerLocation.setCountry("BE");
			signerLocation.setStateOrProvince("Luxembourg");
			signerLocation.setPostalCode("1234");
			signerLocation.setLocality("SimCity");
			bLevelParameters.setSignerLocation(signerLocation);

			List<CommitmentType> commitmentTypeIndications = new ArrayList<>();
			commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfOrigin);
			commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfApproval);
			bLevelParameters.setCommitmentTypeIndications(commitmentTypeIndications);

			CommonCertificateVerifier verifier = new CommonCertificateVerifier();
			XAdESService service = new XAdESService(verifier);
			service.setTspSource(getTSPSource());

			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
			
			// signedDocument.save("target/signed.xml");

			testFinalDocument(signedDocument);
		}
		
	}
	
	@Test
	public void envelopedSignatureXPath2FilterTest() throws IOException {

		prepareXmlDoc();

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			List<DSSTransform> transforms = new ArrayList<>();
			// tag::demoEnvelopedXPath2FilterTransform[]
			// import eu.europa.esig.dss.xades.reference.DSSTransform;
			// import eu.europa.esig.dss.xades.reference.XPath2FilterTransform;

			DSSTransform envelopedTransform = new XPath2FilterTransform("descendant::ds:Signature", "subtract");
			// end::demoEnvelopedXPath2FilterTransform[]
			transforms.add(envelopedTransform);
			
			List<DSSReference> references = new ArrayList<>();
			DSSReference dssReference = new DSSReference();
			dssReference.setContents(toSignDocument);
			dssReference.setId("r-" + toSignDocument.getName());
			dssReference.setTransforms(transforms);
			dssReference.setUri("");
			dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
			references.add(dssReference);

			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
			parameters.setReferences(references);
			
			parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
			parameters.setSigningCertificate(privateKey.getCertificate());
			parameters.setCertificateChain(privateKey.getCertificateChain());

			BLevelParameters bLevelParameters = parameters.bLevel();

			bLevelParameters.setClaimedSignerRoles(Arrays.asList("Manager"));

			SignerLocation signerLocation = new SignerLocation();
			signerLocation.setCountry("BE");
			signerLocation.setStateOrProvince("Luxembourg");
			signerLocation.setPostalCode("1234");
			signerLocation.setLocality("SimCity");
			bLevelParameters.setSignerLocation(signerLocation);

			List<CommitmentType> commitmentTypeIndications = new ArrayList<>();
			commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfOrigin);
			commitmentTypeIndications.add(CommitmentTypeEnum.ProofOfApproval);
			bLevelParameters.setCommitmentTypeIndications(commitmentTypeIndications);

			CommonCertificateVerifier verifier = new CommonCertificateVerifier();
			XAdESService service = new XAdESService(verifier);
			service.setTspSource(getTSPSource());

			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
			
			// signedDocument.save("target/signed.xml");

			testFinalDocument(signedDocument);
		}
		
	}

	@Test
	public void envelopedSignatureXSLTTransformTest() throws IOException {

		prepareXmlDoc();

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::demoEnvelopedXSLTTransform[]
			// import eu.europa.esig.dss.xades.reference.DSSTransform;
			// import eu.europa.esig.dss.xades.reference.XsltTransform;
			// import eu.europa.esig.dss.DomUtils;
			// import org.w3c.dom.Document;

			// Create XSLT transform DOM
			Document xsltTemplate = DomUtils.buildDOM(
					"<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">"
					+ "<xsl:template match=\"/\">"
					+ "<xsl:apply-templates select=\"//*[@Id='hello']\" />"
					+ "</xsl:template>"
					+ "</xsl:stylesheet>");

			DSSTransform xPathTransform = new XsltTransform(xsltTemplate);
			// end::demoEnvelopedXSLTTransform[]

			List<DSSReference> references = new ArrayList<>();

			DSSReference dssReference = new DSSReference();
			dssReference.setId("DSS-REF-1");
			dssReference.setUri("");
			dssReference.setContents(toSignDocument);
			dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);

			dssReference.setTransforms(Arrays.asList(xPathTransform));
			references.add(dssReference);

			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
			parameters.setReferences(references);

			parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);
			parameters.setSigningCertificate(privateKey.getCertificate());
			parameters.setCertificateChain(privateKey.getCertificateChain());

			CommonCertificateVerifier verifier = new CommonCertificateVerifier();
			XAdESService service = new XAdESService(verifier);
			service.setTspSource(getTSPSource());

			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

			// signedDocument.save("target/signed.xml");

			testFinalDocument(signedDocument);
		}

	}

}
