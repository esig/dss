package eu.europa.esig.dss.xades.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.c14n.Canonicalizer;
import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterTransform;

public class XAdESLevelBWithPolicyWithTransformsAndPolicyStoreTest extends AbstractXAdESTestSignature {

	private static final String SIGNATURE_POLICY_ID = "urn:sbr:signature-policy:xml:2.0";
	private static final String SIGNATURE_POLICY_URL = "http://www.nltaxonomie.nl/sbr/signature_policy_schema/v2.0/SBR-signature-policy-v2.0.xml";
	private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";

	private static DSSDocument signaturePolicy;

	private XAdESService service;
	private XAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

		signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		signaturePolicy = new FileDocument("src/test/resources/validation/dss2095/SBR-signature-policy-v2.0.xml");

		XmlPolicyWithTransforms xmlPolicyWithTransforms = new XmlPolicyWithTransforms();
		xmlPolicyWithTransforms.setId(SIGNATURE_POLICY_ID);
		xmlPolicyWithTransforms.setSpuri(SIGNATURE_POLICY_URL);
		xmlPolicyWithTransforms.setDigestAlgorithm(DigestAlgorithm.SHA256);

		// Prepare transformations in the proper order
		List<DSSTransform> policyTransforms = new ArrayList<>();
		DSSTransform canonicalization = new CanonicalizationTransform(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
		policyTransforms.add(canonicalization);
		DSSTransform subtractDigestFilter = new XPath2FilterTransform("/*/*[local-name()='SignPolicyDigest']", "subtract");
		policyTransforms.add(subtractDigestFilter);

		xmlPolicyWithTransforms.setTransforms(policyTransforms);

		byte[] binariesAfterTransforms = DSSXMLUtils.applyTransforms(signaturePolicy, policyTransforms);
		xmlPolicyWithTransforms.setDigestValue(DSSUtils.digest(DigestAlgorithm.SHA256, binariesAfterTransforms));

		signatureParameters.bLevel().setSignaturePolicy(xmlPolicyWithTransforms);

		service = new XAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected DSSDocument sign() {
		DSSDocument signedDocument = super.sign();

		SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
		signaturePolicyStore.setId("sps-" + signatureParameters.getDeterministicId());
		signaturePolicyStore.setSignaturePolicyContent(signaturePolicy);
		SpDocSpecification spDocSpec = new SpDocSpecification();
		spDocSpec.setId(SIGNATURE_POLICY_ID);
		spDocSpec.setDescription(SIGNATURE_POLICY_DESCRIPTION);
		signaturePolicyStore.setSpDocSpecification(spDocSpec);
		DSSDocument signedDocumentWithSignaturePolicyStore = service.addSignaturePolicyStore(signedDocument,
				signaturePolicyStore);
		assertNotNull(signedDocumentWithSignaturePolicyStore);

		return signedDocumentWithSignaturePolicyStore;
	}

	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		validator.setSignaturePolicyProvider(new SignaturePolicyProvider()); // empty instance
		return validator;
	}

	@Override
	protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyIdentifier(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isPolicyPresent());

		assertTrue(signature.isPolicyPresent());
		assertTrue(signature.isPolicyIdentified());
		assertTrue(signature.isPolicyStatus());
		assertTrue(signature.isPolicyDigestAlgorithmsEqual());

		assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
		assertEquals(SIGNATURE_POLICY_URL, signature.getPolicyUrl());
		assertEquals(2, signature.getPolicyTransforms().size());

		assertNotNull(signature.getPolicyDigestAlgoAndValue());
		assertEquals(DigestAlgorithm.SHA256, signature.getPolicyDigestAlgoAndValue().getDigestMethod());
		assertTrue(Utils.isArrayNotEmpty(signature.getPolicyDigestAlgoAndValue().getDigestValue()));
	}

	@Override
	protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
		super.checkSignaturePolicyStore(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyStoreId());
		assertEquals(SIGNATURE_POLICY_DESCRIPTION, signature.getPolicyStoreDescription());

		XmlDigestAlgoAndValue policyStoreDigestAlgoAndValue = signature.getPolicyStoreDigestAlgoAndValue();
		assertNotNull(policyStoreDigestAlgoAndValue);
		assertNotNull(signature.getPolicyStoreDigestAlgoAndValue().getDigestMethod());
		assertTrue(Utils.isArrayNotEmpty(policyStoreDigestAlgoAndValue.getDigestValue()));

		XmlDigestAlgoAndValue policyDigestAlgoAndValue = signature.getPolicyDigestAlgoAndValue();
		assertEquals(policyDigestAlgoAndValue.getDigestMethod(), policyStoreDigestAlgoAndValue.getDigestMethod());
		assertArrayEquals(policyDigestAlgoAndValue.getDigestValue(), policyStoreDigestAlgoAndValue.getDigestValue());

		// transforms applied
		assertNotEquals(signaturePolicy.getDigest(policyDigestAlgoAndValue.getDigestMethod()),
				Utils.toBase64(policyDigestAlgoAndValue.getDigestValue()));
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
