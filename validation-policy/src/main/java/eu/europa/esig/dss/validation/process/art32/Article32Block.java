package eu.europa.esig.dss.validation.process.art32;

import java.util.Date;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.jaxb.detailedreport.XmlArticle32Block;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedList;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.art32.qualification.SignatureQualificationBlock;
import eu.europa.esig.dss.validation.process.art32.tl.TLValidationBlock;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class Article32Block {

	private final DiagnosticData diagnosticData;
	private final ValidationPolicy policy;
	private final Date currentTime;

	public Article32Block(DiagnosticData diagnosticData, ValidationPolicy policy, Date currentTime) {
		this.diagnosticData = diagnosticData;
		this.policy = policy;
		this.currentTime = currentTime;
	}

	public XmlArticle32Block execute() {
		XmlArticle32Block block = new XmlArticle32Block();

		// Validate the LOTL
		XmlTrustedList listOfTrustedLists = diagnosticData.getListOfTrustedLists();
		if (listOfTrustedLists != null) {
			TLValidationBlock tlValidation = new TLValidationBlock(listOfTrustedLists, currentTime, policy);
			block.getTLAnalysis().add(tlValidation.execute());
		}

		// Validate used trusted lists
		List<XmlTrustedList> trustedLists = diagnosticData.getTrustedLists();
		if (Utils.isCollectionNotEmpty(trustedLists)) {
			for (XmlTrustedList xmlTrustedList : trustedLists) {
				TLValidationBlock tlValidation = new TLValidationBlock(xmlTrustedList, currentTime, policy);
				block.getTLAnalysis().add(tlValidation.execute());
			}
		}

		// foreach signature, determine the qualification
		Set<SignatureWrapper> allSignatures = diagnosticData.getAllSignatures();
		if (Utils.isCollectionNotEmpty(allSignatures)) {
			for (SignatureWrapper signature : allSignatures) {
				SignatureQualificationBlock sigQualBlock = new SignatureQualificationBlock(signature, diagnosticData, policy);
				block.getSignatureAnalysis().add(sigQualBlock.execute());
			}
		}

		return block;
	}

}
