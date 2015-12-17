package eu.europa.esig.dss.EN319102.bbb.cv;

import eu.europa.esig.dss.EN319102.bbb.AbstractBasicBuildingBlock;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.bbb.cv.checks.ReferenceDataExistenceCheck;
import eu.europa.esig.dss.EN319102.bbb.cv.checks.ReferenceDataIntactCheck;
import eu.europa.esig.dss.EN319102.bbb.cv.checks.SignatureIntactCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy2;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.2.7 Cryptographic verification
 * This building block checks the integrity of the signed data by performing the cryptographic verifications.
 */
public class CryptographicVerification extends AbstractBasicBuildingBlock<XmlCV>  {

	private final TokenProxy token;

	private final ValidationPolicy2 validationPolicy;

	private ChainItem<XmlCV> firstItem;
	private XmlCV result = new XmlCV();

	public CryptographicVerification(TokenProxy token, ValidationPolicy2 validationPolicy) {
		this.token = token;
		this.validationPolicy = validationPolicy;
	}

	@Override
	public void initChain() {
		ChainItem<XmlCV> item = firstItem = referenceDataFound();
		item = item.setNextItem(referenceDataIntact());
		item = item.setNextItem(signatureIntact());
	}

	private ChainItem<XmlCV> referenceDataFound() {
		LevelConstraint constraint = validationPolicy.getReferenceDataExistenceConstraint();
		return new ReferenceDataExistenceCheck(result, token, constraint);
	}

	private ChainItem<XmlCV> referenceDataIntact() {
		LevelConstraint constraint = validationPolicy.getReferenceDataIntactConstraint();
		return new ReferenceDataIntactCheck(result, token, constraint);
	}

	private ChainItem<XmlCV> signatureIntact() {
		LevelConstraint constraint = validationPolicy.getSignatureIntactConstraint();
		return new SignatureIntactCheck(result, token, constraint);
	}

	@Override
	public XmlCV execute() {
		firstItem.execute();
		return result;
	}

}
