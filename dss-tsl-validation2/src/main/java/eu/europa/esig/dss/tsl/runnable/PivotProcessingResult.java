package eu.europa.esig.dss.tsl.runnable;

import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;

public class PivotProcessingResult {

	private final DSSDocument pivot;
	private final List<CertificateToken> lotlSigCerts;

	public PivotProcessingResult(DSSDocument pivot, List<CertificateToken> lotlSigCerts) {
		this.pivot = pivot;
		this.lotlSigCerts = lotlSigCerts;
	}

	public DSSDocument getPivot() {
		return pivot;
	}

	public List<CertificateToken> getLotlSigCerts() {
		return lotlSigCerts;
	}

}
