package eu.europa.esig.dss.tsl.function;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceDigitalIdentityListType;

public class OtherTSLPointerConverter implements Function<OtherTSLPointerType, OtherTSLPointerDTO> {

	@Override
	public OtherTSLPointerDTO apply(OtherTSLPointerType original) {
		String location = original.getTSLLocation();

		List<CertificateToken> certificates = new ArrayList<CertificateToken>();
		ServiceDigitalIdentityListType serviceDigitalIdentities = original.getServiceDigitalIdentities();
		if (serviceDigitalIdentities != null && Utils.isCollectionNotEmpty(serviceDigitalIdentities.getServiceDigitalIdentity())) {
			for (DigitalIdentityListType digitalIdentityList : serviceDigitalIdentities.getServiceDigitalIdentity()) {
				for (DigitalIdentityType digitalIdentity : digitalIdentityList.getDigitalId()) {
					if (Utils.isArrayNotEmpty(digitalIdentity.getX509Certificate())) {
						certificates.add(DSSUtils.loadCertificate(digitalIdentity.getX509Certificate()));
					}
				}
			}
		}

		return new OtherTSLPointerDTO(location, Collections.unmodifiableList(certificates));
	}

}
