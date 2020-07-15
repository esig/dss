package eu.europa.esig.dss.xades.validation.policy;

import java.util.Arrays;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignaturePolicy;
import eu.europa.esig.dss.validation.policy.AbstractSignaturePolicyValidator;

public class XMLSignaturePolicyValidator extends AbstractSignaturePolicyValidator {

	private static final Logger LOG = LoggerFactory.getLogger(XMLSignaturePolicyValidator.class);

	@Override
	public boolean canValidate() {
		SignaturePolicy signaturePolicy = getSignaturePolicy();
		return DomUtils.startsWithXmlPreamble(signaturePolicy.getPolicyContent());
	}

	@Override
	public void validate() {
		setIdentified(true);

		SignaturePolicy signaturePolicy = getSignaturePolicy();
		DSSDocument policyContent = signaturePolicy.getPolicyContent();
		Digest digest = signaturePolicy.getDigest();
		
		byte[] bytesToBeDigested = null;
		Element transformsNode = signaturePolicy.getTransforms();
		if (transformsNode != null) {
			try {
				Transforms transforms = new Transforms(transformsNode, "");
				
				Document document = DomUtils.buildDOM(policyContent);
				XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(document);
	
				XMLSignatureInput xmlSignatureInputOut = transforms.performTransforms(xmlSignatureInput);
				bytesToBeDigested = xmlSignatureInputOut.getBytes();
			} catch (Exception e) {
				String errorMessage  = String.format("Unable to perform transforms on an XML Policy. Reason : %s", e.getMessage());
				LOG.warn(errorMessage, e);
				addError("xmlProcessing", errorMessage);
			}
		} else {
			bytesToBeDigested = DSSUtils.toByteArray(policyContent);
		}
		
		if (digest != null && bytesToBeDigested != null) {
			byte[] recalculatedDigestValue = DSSUtils.digest(digest.getAlgorithm(), bytesToBeDigested);
			if (Arrays.equals(digest.getValue(), recalculatedDigestValue)) {
				setStatus(true);
				setDigestAlgorithmsEqual(true);
			} else {
				addError("general",
						"The policy digest value (" + Utils.toBase64(digest.getValue()) + ") does not match the re-calculated digest value ("
								+ Utils.toBase64(recalculatedDigestValue) + ").");
			}
			
		} else {
			addError("general", "The policy digest value is not defined.");
		}
	}

}
