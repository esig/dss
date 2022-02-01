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
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.enumerations.CommitmentType;
import eu.europa.esig.dss.enumerations.CommitmentTypeEnum;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.BLevelParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.SignerLocation;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.definition.XAdESNamespaces;
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterTransform;
import eu.europa.esig.dss.xades.reference.XPathTransform;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.XMLSignature;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
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
			service.setTspSource(getOnlineTSPSource());

			// Signature process with its 3 stateless steps
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
			
			// signedDocument.save("target/signed.xml");

			testFinalDocument(signedDocument);

			// tag::demoPrefixes[]
			
			// Allows setting of a XAdES namespace (changes a XAdES format)
			// Default : XAdESNamespaces.XADES_132 (produces XAdES 1.3.2)
			parameters.setXadesNamespace(XAdESNamespaces.XADES_132);
			
			// Defines an XmlDSig prefix
			// Default : XAdESNamespaces.XMLDSIG
			parameters.setXmldsigNamespace(new DSSNamespace(XMLSignature.XMLNS, "myPrefix"));
			
			// Defines a XAdES 1.4.1 format prefix
			// Default : XAdESNamespaces.XADES_141
			parameters.setXades141Namespace(XAdESNamespaces.XADES_141);
			
			// end::demoPrefixes[]
		}
		
	}
	
	@Test
	public void base64TransformTest() throws IOException {

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			DSSDocument document = new InMemoryDocument("Hello World!".getBytes(), "Hello.txt", MimeType.BINARY);
			List<DSSTransform> transforms = new ArrayList<>();
			// tag::demoBase64Transform[]
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
			service.setTspSource(getOnlineTSPSource());

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
			service.setTspSource(getOnlineTSPSource());

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
			service.setTspSource(getOnlineTSPSource());

			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
			
			// signedDocument.save("target/signed.xml");

			testFinalDocument(signedDocument);
		}
		
	}

}
