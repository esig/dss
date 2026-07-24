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
package eu.europa.esig.dss.eaa.sd.jwt.creation;

import eu.europa.esig.dss.eaa.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.jades.JWSJsonSerializationParser;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.json.JsonUtil;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Default implementation to create a payload for the SD-JWT VC key binding signature
 *
 */
public class DefaultSDJWTKeyBindingPayloadBuilder implements SDJWTKeyBindingPayloadBuilder {

    /**
     * Default constructor
     */
    public DefaultSDJWTKeyBindingPayloadBuilder() {
        // empty
    }

    @Override
    public DSSDocument buildPayload(final DSSDocument eaa, final List<SDJWTSelectiveDisclosure> disclosures, final SDJWTKeyBindingParameters keyBindingParameters) {
        StringBuilder signedJWT = new StringBuilder();
        JWSCompactSerializationParser compactParser = new JWSCompactSerializationParser(eaa);
        JWSJsonSerializationParser jwsJsonSerializationParser = new JWSJsonSerializationParser(eaa);

        if (compactParser.isSupported()) {
            signedJWT.append(new String(DSSUtils.toByteArray(eaa)));
        } else if (jwsJsonSerializationParser.isSupported()) {
            JWSJsonSerializationObject serializationObject = jwsJsonSerializationParser.parse();
            JWS jws = serializationObject.getSignatures().get(0);
            signedJWT.append(jws.getEncodedHeader());
            signedJWT.append(".");
            signedJWT.append(jws.getEncodedPayload());
            signedJWT.append(".");
            signedJWT.append(jws.getEncodedSignature());
        } else {
            throw new DSSException("The signed EAA must be a JWS Signature");
        }

        signedJWT.append("~");
        if (Utils.isCollectionNotEmpty(disclosures)) {
            for (SDJWTSelectiveDisclosure disclosure : disclosures) {
                signedJWT.append(disclosure.getDisclosure()).append("~");
            }
        }

        DigestAlgorithm digestAlgorithm = keyBindingParameters.getDigestAlgorithm() == null ? DigestAlgorithm.SHA256 : keyBindingParameters.getDigestAlgorithm();
        byte[] digest = DSSUtils.digest(digestAlgorithm, signedJWT.toString().getBytes());

        final Map<String, Object> payload = new LinkedHashMap<>();
        payload.put(SDJWTConstants.ISSUED_AT, DSSUtils.getTimeValueInSeconds(keyBindingParameters.getIssuanceTime().getTime()));
        payload.put(SDJWTConstants.AUDIENCE, keyBindingParameters.getAudience());
        payload.put(SDJWTConstants.NONCE, keyBindingParameters.getNonce());
        payload.put(SDJWTConstants.SD_HASH, DSSJsonUtils.toBase64Url(digest));

        InMemoryDocument result = new InMemoryDocument(JsonUtil.toJson(payload).getBytes());
        result.setMimeType(MimeTypeEnum.JSON);
        return result;
    }

}
