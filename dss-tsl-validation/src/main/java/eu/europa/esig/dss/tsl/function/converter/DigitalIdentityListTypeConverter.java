package eu.europa.esig.dss.tsl.function.converter;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityType;

public class DigitalIdentityListTypeConverter implements Function<DigitalIdentityListType, List<CertificateToken>> {

	private static final Logger LOG = LoggerFactory.getLogger(DigitalIdentityListTypeConverter.class);

	@Override
	public List<CertificateToken> apply(DigitalIdentityListType digitalIdentityList) {
		List<CertificateToken> certificates = new ArrayList<CertificateToken>();
		if (digitalIdentityList != null && Utils.isCollectionNotEmpty(digitalIdentityList.getDigitalId())) {
			for (DigitalIdentityType digitalIdentity : digitalIdentityList.getDigitalId()) {
				if (Utils.isArrayNotEmpty(digitalIdentity.getX509Certificate())) {
					try {
						certificates.add(DSSUtils.loadCertificate(digitalIdentity.getX509Certificate()));
					} catch (Exception e) {
						if (LOG.isDebugEnabled()) {
							LOG.debug(String.format("Unable to load certificate '%s' : ", Utils.toBase64(digitalIdentity.getX509Certificate())), e);
						} else {
							LOG.warn(String.format("Unable to load certificate '%s' (more details with enabled DEBUG mode)",
									Utils.toBase64(digitalIdentity.getX509Certificate())));
						}
					}
				}
			}
		}
		return certificates;
	}

}
