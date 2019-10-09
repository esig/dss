package eu.europa.esig.dss.tsl.utils;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.utils.Utils;

public final class TLValidationUtils {
	
	public static List<CertificateToken> getLOTLAnnouncedSigningCertificates(List<OtherTSLPointer> loltPointers) {
		if (Utils.isCollectionNotEmpty(loltPointers)) {
			return loltPointers.get(0).getCertificates();
		}
		return Collections.emptyList();
	}

}
