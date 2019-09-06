package eu.europa.esig.dss.cookbook.example.sign;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.CommitmentType;
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
import eu.europa.esig.dss.xades.reference.Base64Transform;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.EnvelopedSignatureTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterTransform;
import eu.europa.esig.dss.xades.reference.XPathTransform;
import eu.europa.esig.dss.xades.signature.XAdESService;

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
			List<DSSTransform> transforms = new ArrayList<DSSTransform>();
			// tag::envelopedTransform[]
			DSSTransform envelopedTransform = new EnvelopedSignatureTransform();
			// end::envelopedTransform[]
			transforms.add(envelopedTransform);
			// tag::canonicalizationTransform[]
			DSSTransform canonicalization = new CanonicalizationTransform(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
			// end::canonicalizationTransform[]
			transforms.add(canonicalization);
			
			// Assign reference to the document
			List<DSSReference> references = new ArrayList<DSSReference>();
			DSSReference dssReference = new DSSReference();
			dssReference.setContents(toSignDocument);
			dssReference.setId("r-" + toSignDocument.getName());
			dssReference.setTransforms(transforms);
			// set empty URI to cover the whole document
			dssReference.setUri("");
			dssReference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
			references.add(dssReference);

			// Initialize signature parameters
			XAdESSignatureParameters parameters = new XAdESSignatureParameters();
			parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
			parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
			// set references
			parameters.setReferences(references);

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
			List<String> commitmentTypeIndications = new ArrayList<String>();
			commitmentTypeIndications.add(CommitmentType.ProofOfOrigin.getUri());
			commitmentTypeIndications.add(CommitmentType.ProofOfApproval.getUri());
			bLevelParameters.setCommitmentTypeIndications(commitmentTypeIndications);

			CommonCertificateVerifier verifier = new CommonCertificateVerifier();
			XAdESService service = new XAdESService(verifier);
			service.setTspSource(getOnlineTSPSource());

			// Signature process with its 3 stateless steps
			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
			
			signedDocument.save("target/signed.xml");

			testFinalDocument(signedDocument);
		}
		
	}
	
	@Test
	public void base64TransformTest() throws IOException {

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::base64Transform[]
			DSSDocument document = new InMemoryDocument("Hello World!".getBytes(), "Hello.txt", MimeType.BINARY);
			List<DSSTransform> transforms = new ArrayList<DSSTransform>();
			DSSTransform base64Transform = new Base64Transform();
			transforms.add(base64Transform);
			// end::base64Transform[]
			
			List<DSSReference> references = new ArrayList<DSSReference>();
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

			List<String> commitmentTypeIndications = new ArrayList<String>();
			commitmentTypeIndications.add(CommitmentType.ProofOfOrigin.getUri());
			commitmentTypeIndications.add(CommitmentType.ProofOfApproval.getUri());
			bLevelParameters.setCommitmentTypeIndications(commitmentTypeIndications);

			CommonCertificateVerifier verifier = new CommonCertificateVerifier();
			XAdESService service = new XAdESService(verifier);
			service.setTspSource(getOnlineTSPSource());

			ToBeSigned dataToSign = service.getDataToSign(document, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(document, parameters, signatureValue);
			
			signedDocument.save("target/signed.xml");

			testFinalDocument(signedDocument);
		}
	}
	
	@Test
	public void envelopedSignatureXPathTest() throws IOException {

		prepareXmlDoc();

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
			
			// tag::envelopedXPathTransform[]
			List<DSSTransform> transforms = new ArrayList<DSSTransform>();
			DSSTransform envelopedTransform = new XPathTransform("not(ancestor-or-self::ds:Signature)");
			transforms.add(envelopedTransform);
			// end::envelopedXPathTransform[]
			
			List<DSSReference> references = new ArrayList<DSSReference>();
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

			List<String> commitmentTypeIndications = new ArrayList<String>();
			commitmentTypeIndications.add(CommitmentType.ProofOfOrigin.getUri());
			commitmentTypeIndications.add(CommitmentType.ProofOfApproval.getUri());
			bLevelParameters.setCommitmentTypeIndications(commitmentTypeIndications);

			CommonCertificateVerifier verifier = new CommonCertificateVerifier();
			XAdESService service = new XAdESService(verifier);
			service.setTspSource(getOnlineTSPSource());

			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
			
			signedDocument.save("target/signed.xml");

			testFinalDocument(signedDocument);
		}
		
	}
	
	@Test
	public void envelopedSignatureXPath2FilterTest() throws IOException {

		prepareXmlDoc();

		try (SignatureTokenConnection signingToken = getPkcs12Token()) {

			DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

			// tag::envelopedXPath2FilterTransform[]
			List<DSSTransform> transforms = new ArrayList<DSSTransform>();
			DSSTransform envelopedTransform = new XPath2FilterTransform("descendant::ds:Signature", "subtract");
			transforms.add(envelopedTransform);
			// end::envelopedXPath2FilterTransform[]
			
			List<DSSReference> references = new ArrayList<DSSReference>();
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

			List<String> commitmentTypeIndications = new ArrayList<String>();
			commitmentTypeIndications.add(CommitmentType.ProofOfOrigin.getUri());
			commitmentTypeIndications.add(CommitmentType.ProofOfApproval.getUri());
			bLevelParameters.setCommitmentTypeIndications(commitmentTypeIndications);

			CommonCertificateVerifier verifier = new CommonCertificateVerifier();
			XAdESService service = new XAdESService(verifier);
			service.setTspSource(getOnlineTSPSource());

			ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
			SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
			DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
			
			signedDocument.save("target/signed.xml");

			testFinalDocument(signedDocument);
		}
		
	}

}
