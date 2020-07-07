package eu.europa.esig.dss.jades.validation;

import java.util.List;
import java.util.Objects;

import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.PKIEncoding;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;

public class JAdESOCSPSource extends OfflineOCSPSource {

	private static final long serialVersionUID = -6522217477882736259L;

	private static final Logger LOG = LoggerFactory.getLogger(JAdESOCSPSource.class);

	private final JWS jws;

	public JAdESOCSPSource(JWS jws) {
		Objects.requireNonNull(jws, "JWS cannot be null");
		this.jws = jws;

		extractOCSPValues();
	}

	private void extractOCSPValues() {
		List etsiU = JAdESUtils.getEtsiU(jws);
		if (Utils.isCollectionEmpty(etsiU)) {
			return;
		}

		for (Object item : etsiU) {
			if (item instanceof JSONObject) {
				JSONObject jsonObject = (JSONObject) item;
				JSONObject rVals = (JSONObject) jsonObject.get(JAdESHeaderParameterNames.R_VALS);
				extractRVals(rVals);
			}
		}
	}

	private void extractRVals(JSONObject rVals) {
		if (rVals != null) {
			JSONArray ocspValues = (JSONArray) rVals.get(JAdESHeaderParameterNames.OCSP_VALS);
			if (Utils.isCollectionNotEmpty(ocspValues)) {
				for (Object item : ocspValues) {
					if (item instanceof JSONObject) {
						JSONObject pkiOb = (JSONObject) item;
						String encoding = (String) pkiOb.get(JAdESHeaderParameterNames.ENCODING);
						if (Utils.isStringEmpty(encoding) || Utils.areStringsEqual(PKIEncoding.DER.getUri(), encoding)) {
							String ocspValueDerB64 = (String) pkiOb.get(JAdESHeaderParameterNames.VAL);
							add(ocspValueDerB64, RevocationOrigin.REVOCATION_VALUES);
						} else {
							LOG.warn("Unsupported encoding '{}'", encoding);
						}
					} else {
						LOG.warn("Unsupported type for {} : {}", JAdESHeaderParameterNames.OCSP_VALS, item.getClass());
					}
				}
			}
		}
	}

	private void add(String ocspValueDerB64, RevocationOrigin origin) {
		try {
			addBinary(OCSPResponseBinary.build(DSSRevocationUtils.loadOCSPBase64Encoded(ocspValueDerB64)), origin);
		} catch (Exception e) {
			LOG.error("Unable to extract OCSP from '{}'", ocspValueDerB64, e);
		}
	}
}
