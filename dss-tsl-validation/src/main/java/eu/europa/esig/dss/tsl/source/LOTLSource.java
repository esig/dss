package eu.europa.esig.dss.tsl.source;

import java.util.function.Predicate;

import eu.europa.esig.dss.tsl.function.EULOTLOtherTSLPointer;
import eu.europa.esig.dss.tsl.function.EUTLOtherTSLPointer;
import eu.europa.esig.dss.tsl.function.LOTLSigningCertificatesAnnouncementSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.XMLOtherTSLPointer;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;

public class LOTLSource extends TLSource {

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

	public LOTLSource() {
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
		this.lotlPredicate = lotlPredicate;
	}

	public Predicate<OtherTSLPointerType> getTlPredicate() {
		return tlPredicate;
	}

	public void setTlPredicate(Predicate<OtherTSLPointerType> tlPredicate) {
		this.tlPredicate = tlPredicate;
	}

	public LOTLSigningCertificatesAnnouncementSchemeInformationURI getSigningCertificatesAnnouncementPredicate() {
		return signingCertificatesAnnouncementPredicate;
	}

	public void setSigningCertificatesAnnouncementPredicate(LOTLSigningCertificatesAnnouncementSchemeInformationURI signingCertificatesAnnouncementPredicate) {
		this.signingCertificatesAnnouncementPredicate = signingCertificatesAnnouncementPredicate;
	}

}
