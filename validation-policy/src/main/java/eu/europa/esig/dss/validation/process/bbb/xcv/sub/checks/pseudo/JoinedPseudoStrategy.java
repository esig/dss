package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.pseudo;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class JoinedPseudoStrategy implements PseudoStrategy {

	private static final List<PseudoStrategy> STRATEGIES;

	static {
		STRATEGIES = new ArrayList<PseudoStrategy>();
		STRATEGIES.add(new PseudoAttributeStrategy());
		STRATEGIES.add(new PseudoGermanyStrategy());
	}

	@Override
	public String getPseudo(CertificateWrapper certificate) {
		for (PseudoStrategy strategy : STRATEGIES) {
			String pseudo = strategy.getPseudo(certificate);
			if (Utils.isStringNotEmpty(pseudo)) {
				return pseudo;
			}
		}
		return null;
	}

}
