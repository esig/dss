package eu.europa.esig.dss.jades.validation;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.PKIEncoding;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.utils.Utils;

public class JAdESCRLSource extends OfflineCRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESCRLSource.class);

	private static final long serialVersionUID = -8088419662779006608L;

	private final JWS jws;

	public JAdESCRLSource(JWS jws) {
		Objects.requireNonNull(jws, "JWS cannot be null");
		this.jws = jws;

		extractEtsiU();
	}

	private void extractEtsiU() {
		List<?> etsiU = JAdESUtils.getEtsiU(jws);
		if (Utils.isCollectionEmpty(etsiU)) {
			return;
		}

		for (Object item : etsiU) {
			if (item instanceof Map) {
				Map<?, ?> jsonObject = (Map<?, ?>) item;

				Map<?, ?> rVals = (Map<?, ?>) jsonObject.get(JAdESHeaderParameterNames.R_VALS);
				if (rVals != null) {
					extractCRLValues(rVals, RevocationOrigin.REVOCATION_VALUES);
				}

				Map<?, ?> arVals = (Map<?, ?>) jsonObject.get(JAdESHeaderParameterNames.AR_VALS);
				if (arVals != null) {
					extractCRLValues(arVals, RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES);
				}
			}
		}
	}

	private void extractCRLValues(Map<?, ?> rVals, RevocationOrigin origin) {
		List<?> crlValues = (List<?>) rVals.get(JAdESHeaderParameterNames.CRL_VALS);
		if (Utils.isCollectionNotEmpty(crlValues)) {
			for (Object item : crlValues) {
				if (item instanceof Map) {
					Map<?, ?> pkiOb = (Map<?, ?>) item;
					String encoding = (String) pkiOb.get(JAdESHeaderParameterNames.ENCODING);
					if (Utils.isStringEmpty(encoding) || Utils.areStringsEqual(PKIEncoding.DER.getUri(), encoding)) {
						String crlValueDerB64 = (String) pkiOb.get(JAdESHeaderParameterNames.VAL);
						add(crlValueDerB64, origin);
					} else {
						LOG.warn("Unsupported encoding '{}'", encoding);
					}
				} else {
					LOG.warn("Unsupported type for {} : {}", JAdESHeaderParameterNames.CRL_VALS, item.getClass());
				}
			}
		}
	}

	private void add(String crlValueDerB64, RevocationOrigin origin) {
		try {
			addBinary(CRLUtils.buildCRLBinary(Utils.fromBase64(crlValueDerB64)), origin);
		} catch (Exception e) {
			LOG.error("Unable to extract CRL from '{}'", crlValueDerB64, e);
		}
	}

}
