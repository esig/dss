package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.pseudo;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public class PseudoGermanyStrategy implements PseudoStrategy {

	private static final String GERMANY_COUNTRY_CODE = "DE";

	private static final String PSEUDO_SUFFIX = ":PN";

	@Override
	public String getPseudo(CertificateWrapper certificate) {
		if (GERMANY_COUNTRY_CODE.equals(certificate.getCountryName())) {
			String cn = certificate.getCommonName();
			if (Utils.endsWithIgnoreCase(cn, PSEUDO_SUFFIX)) {
				return cn.replace(PSEUDO_SUFFIX, "");
			}
		}
		return null;
	}

}
