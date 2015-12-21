package eu.europa.esig.dss.EN319102.bbb.sav;

import eu.europa.esig.dss.EN319102.bbb.AbstractBasicBuildingBlock;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.bbb.sav.checks.ContentHintsCheck;
import eu.europa.esig.dss.EN319102.bbb.sav.checks.ContentIdentifierCheck;
import eu.europa.esig.dss.EN319102.bbb.sav.checks.ContentTypeCheck;
import eu.europa.esig.dss.EN319102.bbb.sav.checks.SigningTimeCheck;
import eu.europa.esig.dss.EN319102.bbb.sav.checks.StructuralValidationCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.validation.policy.ValidationPolicy2;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.ValueConstraint;

/**
 * 5.2.8 Signature acceptance validation (SAV)
 * This building block covers any additional verification to be performed on the signature itself or on the attributes of the signature ETSI EN 319 132-1
 */
public class SignatureAcceptanceValidation extends AbstractBasicBuildingBlock<XmlSAV> {

	private final SignatureWrapper signature;
	private final ValidationPolicy2 validationPolicy;

	private ChainItem<XmlSAV> firstItem;
	private XmlSAV result = new XmlSAV();

	public SignatureAcceptanceValidation(SignatureWrapper signature, ValidationPolicy2 validationPolicy) {
		this.signature = signature;
		this.validationPolicy = validationPolicy;
	}

	@Override
	public void initChain() {
		ChainItem<XmlSAV> item = firstItem = structuralValidation();

		// signing-time
		item = item.setNextItem(signingTime());

		// content-type
		item = item.setNextItem(contentType());

		// content-hints
		item = item.setNextItem(contentHints());

		// TODO content-reference

		// content-identifier
		item = item.setNextItem(contentIdentifier());
	}

	private ChainItem<XmlSAV> structuralValidation() {
		LevelConstraint constraint = validationPolicy.getStructuralValidationConstraint();
		return new StructuralValidationCheck(result, signature, constraint);
	}

	private ChainItem<XmlSAV> signingTime() {
		LevelConstraint constraint = validationPolicy.getSigningTimeConstraint();
		return new SigningTimeCheck(result, signature, constraint);
	}

	private ChainItem<XmlSAV> contentType() {
		ValueConstraint constraint = validationPolicy.getContentTypeConstraint();
		return new ContentTypeCheck(result, signature, constraint);
	}

	private ChainItem<XmlSAV> contentHints() {
		ValueConstraint constraint = validationPolicy.getContentHintsConstraint();
		return new ContentHintsCheck(result, signature, constraint);
	}

	private ChainItem<XmlSAV> contentIdentifier() {
		ValueConstraint constraint = validationPolicy.getContentIdentifierConstraint();
		return new ContentIdentifierCheck(result, signature, constraint);
	}

	@Override
	public XmlSAV execute() {
		firstItem.execute();
		return result;
	}

}
