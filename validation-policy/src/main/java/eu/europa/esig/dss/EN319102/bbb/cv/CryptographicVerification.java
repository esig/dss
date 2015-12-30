package eu.europa.esig.dss.EN319102.bbb.cv;

import eu.europa.esig.dss.EN319102.bbb.AbstractBasicBuildingBlock;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.bbb.cv.checks.ReferenceDataExistenceCheck;
import eu.europa.esig.dss.EN319102.bbb.cv.checks.ReferenceDataIntactCheck;
import eu.europa.esig.dss.EN319102.bbb.cv.checks.SignatureIntactCheck;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.2.7 Cryptographic verification
 * This building block checks the integrity of the signed data by performing the cryptographic verifications.
 * Processing
 * The first and second steps as well as the Data To Be Signed depend on the signature type. The technical details on how
 * to do this correctly are out of scope for the present document. See ETSI EN 319 122-1 [i.2], ETSI EN 319 122-2 [i.3],
 * ETSI EN 319 132-1 [i.4], ETSI EN 319 132-2 [i.5], ETSI EN 319 142-1 [i.6], ETSI EN 319 142-2 [i.7] and IETF
 * RFC 3852 [i.8] for details.
 * 1) The building block shall obtain the signed data object(s) if not provided in the inputs (e.g. by dereferencing an
 * URI present in the signature). If the signed data object(s) cannot be obtained, the building block shall return
 * the indication INDETERMINATE with the sub-indication SIGNED_DATA_NOT_FOUND.
 * 2) The SVA shall check the integrity of the signed data objects. In case of failure, the building block shall return
 * the indication FAILED with the sub-indication HASH_FAILURE.
 * 3) The building block shall verify the cryptographic signature using the public key extracted from the signing
 * certificate in the chain, the signature value and the signature algorithm extracted from the signature. If this
 * cryptographic verification outputs a success indication, the building block shall return the indication PASSED.
 * 4) Otherwise, the building block shall return the indication FAILED and the sub-indication
 * SIG_CRYPTO_FAILURE.
 */
public class CryptographicVerification extends AbstractBasicBuildingBlock<XmlCV> {

	private final TokenProxy token;

	private final ValidationPolicy validationPolicy;

	private ChainItem<XmlCV> firstItem;
	private XmlCV result = new XmlCV();

	public CryptographicVerification(TokenProxy token, ValidationPolicy validationPolicy) {
		this.token = token;
		this.validationPolicy = validationPolicy;
	}

	@Override
	public void initChain() {
		ChainItem<XmlCV> item = firstItem = referenceDataFound(); 	// (1)
		item = item.setNextItem(referenceDataIntact());				// (2)
		item = item.setNextItem(signatureIntact());					// (4)
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
