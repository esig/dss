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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORNull;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORObjectFactory;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.attestation.common.key.DefaultPublicKeyInfoFactory;
import eu.europa.esig.dss.attestation.common.key.PublicKeyInfo;
import eu.europa.esig.dss.attestation.common.key.PublicKeyInfoFactory;
import eu.europa.esig.dss.attestation.mdoc.key.COSEKeyBuilder;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * This class provides a set of methods to build Session transcript object as defined in
 * ISO/IEC 18013-5 "9.1.5.1 Session transcript".
 *
 */
public class SessionTranscriptBuilder {

    /**
     * The factory is used to build a representation of a key from a {@code java.security.PublicKey}
     * Default : {@code DefaultPublicKeyInfoFactory}
     */
    private PublicKeyInfoFactory publicKeyInfoFactory = new DefaultPublicKeyInfoFactory();

    /**
     * The version of the device engagement structure, in the current version of this document its value shall be “1.0”
     */
    private String deviceEngagementVersion = "1.0";

    /**
     * The cipher suite identifier of the device key, as defined in 9.1.5.2
     */
    private EllipticCurve eDeviceCipherSuiteIdentifier;

    /**
     * The device key
     */
    private PublicKey eDeviceKey;

    /**
     * Defines the WebAPI server retrieval method
     */
    private CBORObject webApi;

    /**
     * Defines the OIDC server retrieval method
     */
    private CBORObject oidc;

    /**
     * The use of ProtocolInfo is RFU
     */
    private CBORObject protocolInfo;

    /**
     * Map of other optional properties for the DeviceEngagement object
     */
    private Map<Integer, CBORObject> deviceEngagementOtherMap = new HashMap<>();

    /**
     * The mdoc reader key
     */
    private PublicKey eReaderKey;

    /**
     * Binary value of the Handover Select Message
     * */
    private byte[] handoverSelectMessage;

    /**
     * Binary value of the Handover Request Message,
     * shall be null if NFC Static Handover was used
     */
    private byte[] handoverRequestMessage;

    /**
     * Default constructor
     */
    protected SessionTranscriptBuilder() {
        // empty
    }

    /**
     * Creates a builder for the QR Handover session, if device engagement using QR code (see 8.2.2.3) was used
     *
     * @return {@link SessionTranscriptBuilder}
     */
    public static QRHandoverSessionTranscriptBuilder qrHandover() {
        return new QRHandoverSessionTranscriptBuilder();
    }

    /**
     * Creates a builder for the NFC Handover session, if device engagement using NFC (see 8.2.2.1) was used
     *
     * @param handoverSelectMessage binary value of the Handover Select Message
     * @param handoverRequestMessage binary value of the Handover Request Message
     * @return {@link SessionTranscriptBuilder}
     */
    public static SessionTranscriptBuilder nfcHandover(byte[] handoverSelectMessage, byte[] handoverRequestMessage) {
        Objects.requireNonNull(handoverSelectMessage, "Handover Select Message cannot be null!");
        SessionTranscriptBuilder builder = new SessionTranscriptBuilder();
        builder.handoverSelectMessage = handoverSelectMessage;
        builder.handoverRequestMessage = handoverRequestMessage;
        return builder;
    }

    /**
     * Creates a builder for the NFC Static Handover session, if device engagement using NFC (see 8.2.2.1) was used
     *
     * @param handoverSelectMessage binary value of the Handover Select Message
     * @return {@link SessionTranscriptBuilder}
     */
    public static SessionTranscriptBuilder nfcStaticHandover(byte[] handoverSelectMessage) {
        Objects.requireNonNull(handoverSelectMessage, "Handover Select Message cannot be null!");
        SessionTranscriptBuilder builder = new SessionTranscriptBuilder();
        builder.handoverSelectMessage = handoverSelectMessage;
        return builder;
    }

    /**
     * (Optional) allows modifying the default behavior for a public key computation from a {@code java.security.PublicKey}.
     * Default : an instance of {@code DefaultPublicKeyInfoFactory} is used, relying on JDK 8 and BouncyCastle utility methods.
     *
     * @param publicKeyInfoFactory {@link DefaultPublicKeyInfoFactory}
     */
    public void setPublicKeyInfoFactory(PublicKeyInfoFactory publicKeyInfoFactory) {
        Objects.requireNonNull(publicKeyInfoFactory, "PublicKeyInfoFactory cannot be null!");
        this.publicKeyInfoFactory = publicKeyInfoFactory;
    }

    /**
     * (Optional) Sets the version of the device engagement structure, in the current version of this document its
     * value shall be “1.0”.
     * Default : "1.0"
     *
     * @param version {@link String}
     * @return this {@link SessionTranscriptBuilder}
     */
    public SessionTranscriptBuilder version(String version) {
        Objects.requireNonNull(version, "Version cannot be null!");
        this.deviceEngagementVersion = version;
        return this;
    }

    /**
     * Sets two mandatory element identifying the electronic device key.
     * The first element is the cipher suite identifier, defined in 9.1.5.2.
     * The second element is EdeviceKeyBytes, defined in 9.1.1.4.
     *
     * @param cipherSuiteIdentifier {@link EllipticCurve}
     * @param eDeviceKey {@link PublicKey}
     * @return this {@link SessionTranscriptBuilder}
     */
    public SessionTranscriptBuilder security(EllipticCurve cipherSuiteIdentifier, PublicKey eDeviceKey) {
        Objects.requireNonNull(cipherSuiteIdentifier, "Cipher suite identifier cannot be null!");
        Objects.requireNonNull(eDeviceKey, "eDevice Key cannot be null!");
        this.eDeviceCipherSuiteIdentifier = cipherSuiteIdentifier;
        this.eDeviceKey = eDeviceKey;
        return this;
    }

    /**
     * (Optional) Sets optional information on the WebAPI server retrieval method when supported by the mdoc.
     *
     * @param version {@link Integer} version
     * @param issuerUrl {@link String} issuer URL
     * @param serverRetrievalToken {@link String} server retrieval token
     * @return this {@link SessionTranscriptBuilder}
     */
    public SessionTranscriptBuilder webApiServerRetrievalMethod(Integer version, String issuerUrl, String serverRetrievalToken) {
        CBORArray webApi = new CBORArray();
        webApi.add(version);
        webApi.add(issuerUrl);
        webApi.add(serverRetrievalToken);
        this.webApi = webApi;
        return this;
    }

    /**
     * (Optional) Sets optional information on the OIDC server retrieval method when supported by the mdoc.
     *
     * @param version {@link Integer} version
     * @param issuerUrl {@link String} issuer URL
     * @param serverRetrievalToken {@link String} server retrieval token
     * @return this {@link SessionTranscriptBuilder}
     */
    public SessionTranscriptBuilder oidcServerRetrievalMethod(Integer version, String issuerUrl, String serverRetrievalToken) {
        CBORArray oidc = new CBORArray();
        oidc.add(version);
        oidc.add(issuerUrl);
        oidc.add(serverRetrievalToken);
        this.oidc = oidc;
        return this;
    }

    /**
     * (Optional) Sets protocol information to ensure the DeviceEngagement remains applicable to future solutions and updates,
     * the contents of the ProtocolInfo are RFU in consideration for defining protocol information.
     * The method takes any Object, but it shall be supported by the implementation.
     * To ensure the implementation supports the object, please use an instance of {@code CBORObject} class.
     *
     * @param protocolInfo {@link Object} the use of ProtocolInfo is RFU
     * @return this {@link SessionTranscriptBuilder}
     */
    public SessionTranscriptBuilder protocolInfo(Object protocolInfo) {
        this.protocolInfo = CBORObjectFactory.toCBORObject(protocolInfo);
        return this;
    }

    /**
     * (Optional) Allows adding other information on the Device Engagement object.
     * The method takes any Object, but it shall be supported by the implementation.
     * To ensure the implementation supports the object, please use an instance of {@code CBORObject} class.
     *
     * @param label {@link Integer} map label identifier value
     * @param value {@link Object}
     * @return this {@link SessionTranscriptBuilder}
     */
    public SessionTranscriptBuilder otherDeviceEngagementInfo(Integer label, Object value) {
        Objects.requireNonNull(label, "Label cannot by null!");
        if (label > -1 && label < 5) {
            throw new IllegalArgumentException(String.format("The DeviceEngagement label value '%s' is reserved!", label));
        }
        this.deviceEngagementOtherMap.put(label, CBORObjectFactory.toCBORObject(value));
        return this;
    }

    /**
     * Sets the public key of the mdoc reader device generated for the session, as defined in 9.1.1.4.
     *
     * @param eReaderKey {@link PublicKey}
     * @return this {@link SessionTranscriptBuilder}
     */
    public SessionTranscriptBuilder eReaderKey(PublicKey eReaderKey) {
        Objects.requireNonNull(eReaderKey, "eReader Key cannot be null!");
        this.eReaderKey = eReaderKey;
        return this;
    }

    /**
     * Builds the session transcript document, containing the SessionTranscript CBOR serialized object,
     * to be used within a ReaderAuthentication or/and DeviceAuthentication.
     * NOTE: The returned object is SessionTranscript and not SessionTranscriptBytes.
     * <p>
     * {@code
     *     SessionTranscriptBytes = #6.24(bstr .cbor SessionTranscript)
     *     SessionTranscript = [
     *         DeviceEngagementBytes,
     *         EReaderKeyBytes,
     *         Handover
     *     ]
     * }
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument build() {
        final CBORObject sessionTranscript = buildCbor();
        return new InMemoryDocument(CBORUtils.serializeCborObject(sessionTranscript));
    }

    /**
     * Builds the session transcript CBOR object, containing the SessionTranscript CBOR serialized object,
     * to be used within a ReaderAuthentication or/and DeviceAuthentication.
     * NOTE: The returned object is SessionTranscript and not SessionTranscriptBytes.
     * <p>
     * {@code
     *     SessionTranscriptBytes = #6.24(bstr .cbor SessionTranscript)
     *     SessionTranscript = [
     *         DeviceEngagementBytes,
     *         EReaderKeyBytes,
     *         Handover
     *     ]
     * }
     *
     * @return {@link CBORObject}
     */
    public CBORObject buildCbor() {
        final CBORArray sessionTranscript = new CBORArray();

        CBORMap deviceEngagement = buildDeviceEngagement();
        sessionTranscript.add(CBORUtils.toCborBtsrWrappedTagged(deviceEngagement)); // DeviceEngagementBytes

        CBORMap eReaderKey = buildEReaderKey();
        sessionTranscript.add(CBORUtils.toCborBtsrWrappedTagged(eReaderKey)); // EReaderKeyBytes

        CBORObject handover = buildHandover();
        sessionTranscript.add(handover);

        return sessionTranscript;
    }

    /**
     * Builds DeviceEngagement object as defined in "8.2.1.1 Device engagement structure"
     * <p>
     * {@code
     *     DeviceEngagement =
     *     {
     *         0: tstr,            ; Version
     *         1: Security,
     *         ? 2: DeviceRetrievalMethods, ; Is absent if NFC is used for device engagement
     *         ? 3: ServerRetrievalMethods,
     *         ? 4: ProtocolInfo,
     *         * int => any
     *     }
     * }
     *
     * @return {@link CBORMap}
     */
    protected CBORMap buildDeviceEngagement() {
        Objects.requireNonNull(deviceEngagementVersion, "DeviceEngagement version cannot be null!");
        Objects.requireNonNull(eDeviceCipherSuiteIdentifier, "DeviceEngagement Security Cipher suite identifier is not provided! Please use #security method.");
        Objects.requireNonNull(eDeviceKey, "DeviceEngagement Security EDeviceKeyBytes is not provided! Please use #security method.");

        CBORMap deviceEngagement = new CBORMap();
        deviceEngagement.put(0L, deviceEngagementVersion);

        CBORArray security = new CBORArray();
        security.add(eDeviceCipherSuiteIdentifier.getCOSEValue());

        CBORMap eDeviceKeyCbor = buildCOSEKey(eDeviceKey);
        CBORByteString eDeviceKeyBytes = CBORUtils.toCborBtsrWrappedTagged(eDeviceKeyCbor);
        security.add(eDeviceKeyBytes);

        deviceEngagement.put(1L, security);

        // 2: DeviceRetrievalMethods is not defined by default (see QRHandoverSessionTranscriptBuilder)

        if (webApi != null || oidc != null) {
            CBORMap serverRetrievalMethods = new CBORMap();
            if (webApi != null) {
                serverRetrievalMethods.put("webApi", webApi);
            }
            if (oidc != null) {
                serverRetrievalMethods.put("oidc", oidc);
            }
            deviceEngagement.put(3L, serverRetrievalMethods);
        }
        if (protocolInfo != null) {
            deviceEngagement.put(4L, protocolInfo);
        }
        if (Utils.isMapNotEmpty(deviceEngagementOtherMap)) {
            for (Map.Entry<Integer, CBORObject> entry : deviceEngagementOtherMap.entrySet()) {
                deviceEngagement.put(entry.getKey(), entry.getValue());
            }
        }
        return deviceEngagement;
    }

    /**
     * Builds eReaderKey as defined in 9.1.1.4
     * <p>
     * {@code
     *     EReaderKey = COSE_Key                           ; Containing EReaderKey.Pub
     * }
     * @return {@link CBORMap}
     */
    protected CBORMap buildEReaderKey() {
        Objects.requireNonNull(this.eReaderKey, "eReaderKey is not provided! Please use #eReaderKey method.");
        return buildCOSEKey(this.eReaderKey);
    }

    /**
     * Builds a COSE_Key representation of a device's {@code PublicKey}
     *
     * @param publicKey {@link PublicKey}
     * @return {@link CBORMap}
     */
    protected CBORMap buildCOSEKey(PublicKey publicKey) {
        PublicKeyInfo publicKeyInfo = publicKeyInfoFactory.create(publicKey);
        return new COSEKeyBuilder(publicKeyInfo).create();
    }

    /**
     * Builds Handover object as defined in "9.1.5.1 Session transcript"
     * <p>
     * {@code
     *     Handover = QRHandover / NFCHandover
     *     QRHandover= null
     *     NFCHandover = [
     *         bstr        ; Binary value of the Handover Select Message
     *         bstr / null ; Binary value of the Handover Request Message,
     *                     ; shall be null if NFC Static Handover was used
     *     ]
     * }
     *
     * @return {@link CBORObject}
     */
    protected CBORObject buildHandover() {
        CBORArray handover = new CBORArray();
        handover.add(handoverSelectMessage);
        handover.add(handoverRequestMessage);
        return handover;
    }

    /**
     * Session transaction build used for a QR Handover mechanism
     */
    public static class QRHandoverSessionTranscriptBuilder extends SessionTranscriptBuilder {

        /**
         * An array that shall contain one or more DeviceRetrievalMethod arrays
         * when performing device engagement using the QR code
         */
        private List<CBORObject> deviceRetrievalMethods = new ArrayList<>();

        /**
         * Default constructor
         */
        protected QRHandoverSessionTranscriptBuilder() {
            super();
        }

        @Override
        public QRHandoverSessionTranscriptBuilder version(String version) {
            return (QRHandoverSessionTranscriptBuilder) super.version(version);
        }

        @Override
        public QRHandoverSessionTranscriptBuilder security(EllipticCurve cipherSuiteIdentifier, PublicKey eDeviceKey) {
            return (QRHandoverSessionTranscriptBuilder) super.security(cipherSuiteIdentifier, eDeviceKey);
        }

        @Override
        public QRHandoverSessionTranscriptBuilder webApiServerRetrievalMethod(Integer version, String issuerUrl, String serverRetrievalToken) {
            return (QRHandoverSessionTranscriptBuilder) super.webApiServerRetrievalMethod(version, issuerUrl, serverRetrievalToken);
        }

        @Override
        public QRHandoverSessionTranscriptBuilder oidcServerRetrievalMethod(Integer version, String issuerUrl, String serverRetrievalToken) {
            return (QRHandoverSessionTranscriptBuilder) super.oidcServerRetrievalMethod(version, issuerUrl, serverRetrievalToken);
        }

        @Override
        public QRHandoverSessionTranscriptBuilder protocolInfo(Object protocolInfo) {
            return (QRHandoverSessionTranscriptBuilder) super.protocolInfo(protocolInfo);
        }

        @Override
        public QRHandoverSessionTranscriptBuilder otherDeviceEngagementInfo(Integer label, Object value) {
            return (QRHandoverSessionTranscriptBuilder) super.otherDeviceEngagementInfo(label, value);
        }

        @Override
        public QRHandoverSessionTranscriptBuilder eReaderKey(PublicKey eReaderKey) {
            return (QRHandoverSessionTranscriptBuilder) super.eReaderKey(eReaderKey);
        }

        /**
         * Adds a device retrieval option based on the WiFi connection option.
         * This method adds the option to the exiting list of device retrieval methods.
         * <p>
         * {@code
         *     WifiOptions = {
         *         ? 0: tstr,      ; Pass-phrase Info Pass-phrase
         *         ? 1: uint,      ; Channel Info Operating Class
         *         ? 2: uint,      ; Channel Info Channel Number
         *         ? 3: bstr       ; Band Info Supported Bands
         *     }
         * }
         *
         * @param passPhrase {@link String} pass-phrase Info Pass-phrase
         * @param channelInfoOperatingClass {@link Integer} channel Info Operating Class
         * @param channelInfoChannelNumber {@link Integer} channel Info Channel Number
         * @param bandInfoSupportedBands band Info Supported Bands
         * @return this {@link QRHandoverSessionTranscriptBuilder}
         */
        public QRHandoverSessionTranscriptBuilder addWiFiRetrievalOptions(
                String passPhrase, Integer channelInfoOperatingClass, Integer channelInfoChannelNumber, byte[] bandInfoSupportedBands) {
            CBORArray deviceRetrievalMethod = new CBORArray();

            deviceRetrievalMethod.add(3L); // type : Wi-Fi Aware
            deviceRetrievalMethod.add(1L); // version

            CBORMap wifiOptions = new CBORMap();
            if (passPhrase != null) {
                wifiOptions.put(0L, passPhrase);
            }
            if (channelInfoOperatingClass != null) {
                wifiOptions.put(1L, channelInfoOperatingClass);
            }
            if (channelInfoChannelNumber != null) {
                wifiOptions.put(2L, channelInfoChannelNumber);
            }
            if (bandInfoSupportedBands != null) {
                wifiOptions.put(3L, bandInfoSupportedBands);
            }
            deviceRetrievalMethod.add(wifiOptions); // retrievalOptions

            deviceRetrievalMethods.add(deviceRetrievalMethod);

            return this;
        }

        /**
         * Adds a device retrieval option based on the Ble connection option.
         * This method adds the option to the exiting list of device retrieval methods.
         * <p>
         * {@code
         *     BleOptions = {
         *         0 : bool,       ; Indicates support for mdoc peripheral server mode
         *         1 : bool,       ; Indicates support for mdoc central client mode
         *         ? 10 : bstr,    ; UUID for mdoc peripheral server mode
         *         ? 11 : bstr     ; UUID for mdoc client central mode
         *         ? 20 : bstr     ; mdoc BLE Device Address for mdoc peripheral server mode
         *     }
         * }
         *
         * @param peripheralServerMode indicates support for mdoc peripheral server mode
         * @param centralClientMode indicates support for mdoc central client mode
         * @param peripheralServerModeUUID UUID for mdoc peripheral server mode
         * @param clientCentralModeUUID UUID for mdoc client central mode
         * @param bleDeviceAddress mdoc BLE Device Address for mdoc peripheral server mode
         * @return this {@link QRHandoverSessionTranscriptBuilder}
         */
        public QRHandoverSessionTranscriptBuilder addBleRetrievalOptions(boolean peripheralServerMode, boolean centralClientMode,
                byte[] peripheralServerModeUUID, byte[] clientCentralModeUUID, byte[] bleDeviceAddress) {
            CBORArray deviceRetrievalMethod = new CBORArray();

            deviceRetrievalMethod.add(2L); // type : BLE
            deviceRetrievalMethod.add(1L); // version

            CBORMap bleOptions = new CBORMap();
            bleOptions.put(0L, peripheralServerMode);
            bleOptions.put(1L, centralClientMode);
            if (peripheralServerModeUUID != null) {
                bleOptions.put(10L, peripheralServerModeUUID);
            }
            if (clientCentralModeUUID != null) {
                bleOptions.put(11L, clientCentralModeUUID);
            }
            if (bleDeviceAddress != null) {
                bleOptions.put(20L, bleDeviceAddress);
            }
            deviceRetrievalMethod.add(bleOptions); // retrievalOptions

            deviceRetrievalMethods.add(deviceRetrievalMethod);

            return this;
        }

        /**
         * Adds a device retrieval option based on the Ble connection option.
         * This method adds the option to the exiting list of device retrieval methods.
         * <p>
         * {@code
         *     NfcOptions = {
         *         0 : uint,       ; Maximum length of command data field
         *         1 : uint        ; Maximum length of response data field
         *     }
         * }
         * @param commandDataFieldLength {@link Integer} maximum length of command data field
         * @param responseDataFieldLength {@link Integer} maximum length of response data field
         * @return this {@link QRHandoverSessionTranscriptBuilder}
         */
        public QRHandoverSessionTranscriptBuilder addNfcRetrievalOptions(Integer commandDataFieldLength, Integer responseDataFieldLength) {
            Objects.requireNonNull(commandDataFieldLength, "Maximum length of command data field cannot be null!");
            Objects.requireNonNull(responseDataFieldLength, "Maximum length of response data field cannot be null!");

            CBORArray deviceRetrievalMethod = new CBORArray();

            deviceRetrievalMethod.add(1L); // type : NFC
            deviceRetrievalMethod.add(1L); // version

            CBORMap nfcOptions = new CBORMap();
            nfcOptions.put(0L, commandDataFieldLength);
            nfcOptions.put(1L, responseDataFieldLength);
            deviceRetrievalMethod.add(nfcOptions); // retrievalOptions

            deviceRetrievalMethods.add(deviceRetrievalMethod);

            return this;
        }

        @Override
        protected CBORMap buildDeviceEngagement() {
            if (Utils.isCollectionEmpty(deviceRetrievalMethods)) {
                throw new NullPointerException("No DeviceRetrievalMethods have been provided! Please add WiFi, BLE or NFC retrieval options!");
            }

            CBORMap deviceEngagement = super.buildDeviceEngagement();

            CBORArray deviceRetrievalMethodsCbor = new CBORArray();
            for (CBORObject method : deviceRetrievalMethods) {
                deviceRetrievalMethodsCbor.add(method);
            }
            deviceEngagement.put(2L, deviceRetrievalMethodsCbor);

            return deviceEngagement;
        }

        @Override
        protected CBORObject buildHandover() {
            /*
             * QRHandover= null
             */
            return new CBORNull();
        }

    }

}
