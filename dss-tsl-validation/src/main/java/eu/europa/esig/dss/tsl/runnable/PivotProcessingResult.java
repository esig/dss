package eu.europa.esig.dss.tsl.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.CertificateSource;

/**
 * This class contains the pivot and its introduced signing certificates for the
 * LOTL or the next pivot
 */
public class PivotProcessingResult {

	private final DSSDocument pivot;
	private final CertificateSource certificateSource;
	private final String lotlLocation;

	public PivotProcessingResult(DSSDocument pivot, CertificateSource certificateSource, String lotlLocation) {
		this.pivot = pivot;
		this.certificateSource = certificateSource;
		this.lotlLocation = lotlLocation;
	}

	public DSSDocument getPivot() {
		return pivot;
	}

	public CertificateSource getCertificateSource() {
		return certificateSource;
	}

	public String getLotlLocation() {
		return lotlLocation;
	}

}
