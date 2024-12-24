/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.function.converter;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * The class is used to extract {@code CertificateToken}s from a {@code DigitalIdentityListType}
 *
 */
public class DigitalIdentityListTypeConverter implements Function<DigitalIdentityListType, List<CertificateToken>> {

	private static final Logger LOG = LoggerFactory.getLogger(DigitalIdentityListTypeConverter.class);

	/**
	 * Default constructor
	 */
	public DigitalIdentityListTypeConverter() {
		// empty
	}

	@Override
	public List<CertificateToken> apply(DigitalIdentityListType digitalIdentityList) {
		List<CertificateToken> certificates = new ArrayList<>();
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
