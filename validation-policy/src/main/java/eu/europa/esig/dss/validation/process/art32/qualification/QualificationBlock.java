package eu.europa.esig.dss.validation.process.art32.qualification;

import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;

public class QualificationBlock {

	/* Only CA/QC trusted services */
	private final List<XmlTrustedServiceProvider> caQcTsps;

	public QualificationBlock(List<XmlTrustedServiceProvider> caQcTsps) {
		this.caQcTsps = caQcTsps;
	}

}
