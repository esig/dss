package eu.europa.esig.dss.EN319102.validation.vpfbs;

import java.util.Map;

import eu.europa.esig.dss.EN319102.bbb.AbstractBasicBuildingBlock;
import eu.europa.esig.dss.EN319102.bbb.ChainItem;
import eu.europa.esig.dss.EN319102.validation.vpfbs.checks.SignatureBasicBuildingBlocksCheck;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessBasicSignatures;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

/**
 * 5.3 Validation process for Basic Signatures
 */
public class ValidationProcessForBasicSignatures extends AbstractBasicBuildingBlock<XmlValidationProcessBasicSignatures> {

	private final DiagnosticData diagnosticData;

	private final XmlBasicBuildingBlocks signatureBBB;
	private final Map<String, XmlBasicBuildingBlocks> bbbs;

	public ValidationProcessForBasicSignatures(DiagnosticData diagnosticData, XmlBasicBuildingBlocks signatureBBB, Map<String, XmlBasicBuildingBlocks> bbbs) {
		super(new XmlValidationProcessBasicSignatures());

		this.diagnosticData = diagnosticData;
		this.signatureBBB = signatureBBB;
		this.bbbs = bbbs;
	}

	@Override
	protected void initChain() {
		firstItem = basicBuildingBlocks();
	}

	private ChainItem<XmlValidationProcessBasicSignatures> basicBuildingBlocks() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		return new SignatureBasicBuildingBlocksCheck(result, diagnosticData, signatureBBB, bbbs, constraint);
	}

}
