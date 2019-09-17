package eu.europa.esig.dss.tsl.source;

import java.util.Objects;
import java.util.function.Predicate;

import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.function.EULOTLOtherTSLPointer;
import eu.europa.esig.dss.tsl.function.EUTLOtherTSLPointer;
import eu.europa.esig.dss.tsl.function.LOTLSigningCertificatesAnnouncementSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.TrustServicePredicate;
import eu.europa.esig.dss.tsl.function.TrustServiceProviderPredicate;
import eu.europa.esig.dss.tsl.function.XMLOtherTSLPointer;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;

public class LOTLSource {

	/**
	 * LOTL URL
	 */
	private String url;

	/**
	 * Signing certificates for the current LOTL
	 */
	private CertificateSource certificateSource;

	/**
	 * Enable/disable pivot LOTL support
	 */
	private boolean pivotSupport = false;

	/**
	 * Predicate which filters the LOTL
	 * 
	 * Default : filter the XML European list of trusted list (LOTL)
	 */
	private Predicate<OtherTSLPointerType> lotlPredicate = new EULOTLOtherTSLPointer().and(new XMLOtherTSLPointer());

	/**
	 * Predicate which filters the TLs
	 * 
	 * Default : filter all XML trusted lists (TL) for European countries
	 */
	private Predicate<OtherTSLPointerType> tlPredicate = new EUTLOtherTSLPointer().and(new XMLOtherTSLPointer());

	/**
	 * Optional : Predicate which filters the URL where the provided signing
	 * certificates are defined
	 */
	private LOTLSigningCertificatesAnnouncementSchemeInformationURI signingCertificatesAnnouncementPredicate;

	/**
	 * Optional : Predicate which allows to filter the collected trust service
	 * provider(s) from the related trusted list(s).
	 * 
	 * Default : all trust service providers are selected
	 */
	private TrustServiceProviderPredicate trustServiceProviderPredicate;

	/**
	 * Optional : Predicate which allows to filter the collected trust service(s)
	 * from the related trusted list(s).
	 * 
	 * Default : all trust services are selected
	 */
	private TrustServicePredicate trustServicePredicate;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		Objects.requireNonNull(url);
		this.url = url;
	}

	public CertificateSource getCertificateSource() {
		return certificateSource;
	}

	public void setCertificateSource(CertificateSource certificateSource) {
		Objects.requireNonNull(certificateSource);
		this.certificateSource = certificateSource;
	}

	public boolean isPivotSupport() {
		return pivotSupport;
	}

	public void setPivotSupport(boolean pivotSupport) {
		this.pivotSupport = pivotSupport;
	}

	public Predicate<OtherTSLPointerType> getLotlPredicate() {
		return lotlPredicate;
	}

	public void setLotlPredicate(Predicate<OtherTSLPointerType> lotlPredicate) {
		Objects.requireNonNull(lotlPredicate);
		this.lotlPredicate = lotlPredicate;
	}

	public Predicate<OtherTSLPointerType> getTlPredicate() {
		return tlPredicate;
	}

	public void setTlPredicate(Predicate<OtherTSLPointerType> tlPredicate) {
		Objects.requireNonNull(tlPredicate);
		this.tlPredicate = tlPredicate;
	}

	public LOTLSigningCertificatesAnnouncementSchemeInformationURI getSigningCertificatesAnnouncementPredicate() {
		return signingCertificatesAnnouncementPredicate;
	}

	public void setSigningCertificatesAnnouncementPredicate(LOTLSigningCertificatesAnnouncementSchemeInformationURI signingCertificatesAnnouncementPredicate) {
		this.signingCertificatesAnnouncementPredicate = signingCertificatesAnnouncementPredicate;
	}

	public TrustServiceProviderPredicate getTrustServiceProviderPredicate() {
		return trustServiceProviderPredicate;
	}

	public void setTrustServiceProviderPredicate(TrustServiceProviderPredicate trustServiceProviderPredicate) {
		this.trustServiceProviderPredicate = trustServiceProviderPredicate;
	}

	public TrustServicePredicate getTrustServicePredicate() {
		return trustServicePredicate;
	}

	public void setTrustServicePredicate(TrustServicePredicate trustServicePredicate) {
		this.trustServicePredicate = trustServicePredicate;
	}

}
