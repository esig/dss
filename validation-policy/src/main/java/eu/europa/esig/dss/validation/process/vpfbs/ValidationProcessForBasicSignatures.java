package eu.europa.esig.dss.validation.process.vpfbs;

import java.util.Map;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessBasicSignatures;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfbs.checks.SignatureBasicBuildingBlocksCheck;
import eu.europa.esig.dss.validation.wrappers.DiagnosticData;
import eu.europa.esig.dss.validation.wrappers.SignatureWrapper;

/**
 * 5.3 Validation process for Basic Signatures
 */
public class ValidationProcessForBasicSignatures extends Chain<XmlValidationProcessBasicSignatures> {

	private final DiagnosticData diagnosticData;
	private final SignatureWrapper signature;

	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	public ValidationProcessForBasicSignatures(DiagnosticData diagnosticData, SignatureWrapper signature, Map<String, XmlBasicBuildingBlocks> bbbs) {
		super(new XmlValidationProcessBasicSignatures());

		this.diagnosticData = diagnosticData;
		this.signature = signature;
		this.bbbs = bbbs;
	}

	@Override
	protected void initChain() {
		firstItem = basicBuildingBlocks();
	}

	private ChainItem<XmlValidationProcessBasicSignatures> basicBuildingBlocks() {
		return new SignatureBasicBuildingBlocksCheck(result, diagnosticData, bbbs.get(signature.getId()), bbbs, getFailLevelConstraint());
	}

}
