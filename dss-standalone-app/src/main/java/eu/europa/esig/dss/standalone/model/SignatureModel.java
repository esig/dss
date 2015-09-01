package eu.europa.esig.dss.standalone.model;

import javafx.beans.property.ObjectProperty;
import eu.europa.esig.dss.DigestAlgorithm;

public class SignatureModel {

	private ObjectProperty<DigestAlgorithm> digestAlgo;

	public DigestAlgorithm getDigestAlgo() {
		return digestAlgo.get();
	}

	public void setDigestAlgo(DigestAlgorithm digestAlgo) {
		this.digestAlgo.set(digestAlgo);
	}

}
