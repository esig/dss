package eu.europa.esig.dss.tsl.function.converter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.tsl.dto.OtherTSLPointer;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceDigitalIdentityListType;

public class OtherTSLPointerConverter implements Function<OtherTSLPointerType, OtherTSLPointer> {

	@Override
	public OtherTSLPointer apply(OtherTSLPointerType original) {
		return new OtherTSLPointer(original.getTSLLocation(), Collections.unmodifiableList(getCertificates(original.getServiceDigitalIdentities())));
	}

	private List<CertificateToken> getCertificates(ServiceDigitalIdentityListType serviceDigitalIdentities) {
		List<CertificateToken> certificates = new ArrayList<CertificateToken>();
		if (serviceDigitalIdentities != null && Utils.isCollectionNotEmpty(serviceDigitalIdentities.getServiceDigitalIdentity())) {
			DigitalIdentityListTypeConverter converter = new DigitalIdentityListTypeConverter();
			for (DigitalIdentityListType digitalIdentityList : serviceDigitalIdentities.getServiceDigitalIdentity()) {
				certificates.addAll(converter.apply(digitalIdentityList));
			}
		}
		return certificates;
	}

}
